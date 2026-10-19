#!/usr/bin/env python3
"""Unit tests; --namespace additionally requires root in a private net namespace."""
import hashlib
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

NAMESPACE = "--namespace" in sys.argv
if NAMESPACE:
    sys.argv.remove("--namespace")
if os.name == "nt":
    sys.modules["fcntl"] = types.SimpleNamespace()
source = (Path(__file__).resolve().parent.parent / "harden.sh").read_text()
code = source.split("cat <<'FIREWALL_PYTHON'\n", 1)[1].split("\nFIREWALL_PYTHON", 1)[0]
loader = types.ModuleType("firewall_loader")
exec(compile(code, "embedded-firewall-loader", "exec"), loader.__dict__)

POLICY = '''table inet hardening_filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state invalid drop
        ct state established,related accept
        iifname "lo" accept
        iifname "tailscale0" accept comment "preserve Tailscale administration"
        udp dport 41641 accept
        iifname "wg0" accept
        tcp dport { 22, 2222 } ct state new accept
        ip saddr 192.0.2.10 tcp dport 11434 ct state new counter accept
        counter drop
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid drop
        ct state established,related accept
        iifname "tailscale0" accept
        oifname "tailscale0" accept
        counter drop
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
'''
DOCKER = 'iifname "docker0" oifname "eth0" ip saddr 172.17.0.0/16 tcp dport { 53, 80, 443 } counter accept\n'


class UnitTests(unittest.TestCase):
    def test_scope_and_policy(self):
        self.assertIn("policy drop", loader.expand(POLICY))
        self.assertIn('comment "table chain"', loader.expand(POLICY.replace('counter drop', 'counter drop comment "table chain"')))
        for bad in (POLICY + "flush ruleset\n", POLICY.replace("policy drop", "policy accept", 1),
                    POLICY.replace('        counter drop', '        }; delete table ip foreign; {', 1),
                    POLICY.replace('        counter drop', '        include "/tmp/rules"', 1),
                    POLICY.replace("type filter hook input priority filter; policy drop;", "")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                loader.expand(bad)

    def test_api(self):
        self.assertEqual(loader.api_rule("", ""), "")
        self.assertIn("ip saddr 192.0.2.10 tcp dport 11434", loader.api_rule("192.0.2.10", "11434"))
        self.assertIn("ip6 saddr 2001:db8::10", loader.api_rule("2001:db8::10", "443"))
        for source, port in (("", "443"), ("192.0.2.1", ""), ("0.0.0.0/0", "443"),
                             ("0.0.0.0", "443"), ("::", "443"), ("ff02::1", "443"),
                             ("example.test", "443"), ("192.0.2.1", "65536"),
                             ("192.0.2.1; accept", "443"), ("192.0.2.1", "80; accept")):
            with self.subTest(source=source, port=port), self.assertRaises(ValueError):
                loader.api_rule(source, port)

    def test_docker_grammar(self):
        with patch.object(loader, "trusted_read", return_value=DOCKER):
            self.assertIn('dport { 53, 80, 443 }', loader.docker_rules("unused"))
        for bad in ("accept", DOCKER + "}; flush ruleset; {", DOCKER.replace("172.17.0.0/16", "0.0.0.0/0"),
                    DOCKER.replace("443", "65536"), DOCKER.replace('"docker0"', '"br-*"'),
                    'include "/etc/another.nft"', "# empty\n"):
            with self.subTest(bad=bad), patch.object(loader, "trusted_read", return_value=bad), self.assertRaises(ValueError):
                loader.docker_rules("unused")

    def test_transaction_failures_and_noop(self):
        live, state, calls = ["previous policy"], {}, []
        failure = [None]

        def fake_nft(*args, text=None, check=True):
            calls.append((args, text))
            if args in (("-c", "-f", "-"), ("-f", "-")):
                self.assertTrue(text.startswith("add table inet hardening_filter\ndelete table inet hardening_filter\n"))
                if failure[0] == args[0]:
                    raise ValueError("forced nft failure")
                if args[0] == "-f":
                    live[0] = text
            return types.SimpleNamespace(returncode=0, stdout=live[0], stderr="")

        def saved_read(path, directory=None):
            return state.get(path, "")

        with patch.object(loader, "nft", side_effect=fake_nft), patch.object(loader, "trusted_read", side_effect=saved_read), \
                patch.object(loader, "save_atomic", side_effect=lambda p, t: state.update({p: t})):
            for stage in ("-c", "-f"):
                failure[0] = stage
                with self.assertRaises(ValueError):
                    loader.activate(POLICY)
                self.assertEqual(live[0], "previous policy")
            failure[0] = None
            loader.activate(POLICY)
            calls.clear()
            loader.activate(POLICY)
            self.assertFalse(any(c[0] == ("-f", "-") for c in calls))
            live[0] = "external drift"
            loader.activate(POLICY)
            self.assertTrue(any(c[0] == ("-f", "-") for c in calls))
            self.assertFalse(any(c[0][0] in ("delete", "flush") for c in calls))

    def test_no_legacy_delete_or_reload(self):
        shell = source.split("FIREWALL_PYTHON\n}", 1)[1]
        self.assertNotIn("nft delete table", shell)
        self.assertNotIn("run_streamed nft -f", shell)
        self.assertNotIn("ExecStartPre=-/usr/sbin/nft", source)


@unittest.skipUnless(NAMESPACE, "real nft tests require explicit --namespace in Linux CI")
class NamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
            raise RuntimeError("refusing nft test outside a private root network namespace")

    def check_source_boundary(self):
        # Real TCP packets from a second disposable namespace. Never enter the
        # host network namespace or touch a host interface.
        peer = subprocess.Popen(["unshare", "--net", "sleep", "60"])
        server = socket.socket()
        try:
            import time
            for _ in range(100):
                try:
                    if os.readlink(f"/proc/{peer.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                        break
                except FileNotFoundError:
                    pass
                time.sleep(0.01)
            else:
                self.fail("peer network namespace did not start")
            def ip(*args):
                subprocess.run(["ip", *args], check=True, capture_output=True)
            prefix = ["nsenter", "-t", str(peer.pid), "-n"]
            ip("link", "add", "test-server", "type", "veth", "peer", "name", "test-client")
            ip("link", "set", "test-client", "netns", str(peer.pid))
            ip("addr", "add", "192.0.2.1/24", "dev", "test-server")
            ip("link", "set", "test-server", "up")
            for address in ("192.0.2.10/24", "192.0.2.11/24"):
                subprocess.run(prefix + ["ip", "addr", "add", address, "dev", "test-client"], check=True)
            subprocess.run(prefix + ["ip", "link", "set", "test-client", "up"], check=True)
            server.bind(("192.0.2.1", 11434))
            server.listen(8)
            client = ('import socket,sys; s=socket.socket(); s.settimeout(1); '
                      's.bind((sys.argv[1],0)); s.connect(("192.0.2.1",11434))')
            allowed = subprocess.run(prefix + [sys.executable, "-c", client, "192.0.2.10"], capture_output=True)
            denied = subprocess.run(prefix + [sys.executable, "-c", client, "192.0.2.11"], capture_output=True)
            self.assertEqual(allowed.returncode, 0, allowed.stderr)
            self.assertNotEqual(denied.returncode, 0, "unexpected API access from a different source")
        finally:
            server.close()
            peer.terminate()
            peer.wait(timeout=5)
            subprocess.run(["ip", "link", "delete", "test-server"], capture_output=True)

    def test_real_transactions_trust_and_boot(self):
        with tempfile.TemporaryDirectory(prefix="hardening-nft-", dir="/run") as root:
            root = Path(root)
            os.chmod(root, 0o700)
            config = root / "policy.nft"
            fragment = root / "docker.rules"
            original_read = loader.trusted_read
            loader.CONFIG = str(config)
            loader.STATE = str(root / "state")
            loader.LAST_GOOD = str(root / "last-good.nft")
            loader.LOCK = str(root / "lock")
            config.write_text(POLICY)
            fragment.write_text(DOCKER)
            # Exercise the identical FD/ownership walk under a test-only allowed
            # directory. Production retains /etc/nftables.d as its allowlist.
            def scoped_read(path, directory="/etc/nftables.d"):
                return original_read(path, str(root) if directory else None)
            with patch.object(loader, "trusted_read", side_effect=scoped_read):
                self.assertEqual(loader.docker_rules(str(fragment)), DOCKER.strip())
                for mutation in ("mode", "owner", "parent", "symlink", "empty", "missing"):
                    os.chmod(root, 0o700)
                    fragment.unlink(missing_ok=True)
                    fragment.write_text(DOCKER)
                    os.chown(fragment, 0, 0)
                    os.chmod(fragment, 0o600)
                    if mutation == "mode": os.chmod(fragment, 0o666)
                    if mutation == "owner": os.chown(fragment, 65534, 65534)
                    if mutation == "parent": os.chmod(root, 0o777)
                    if mutation == "symlink":
                        fragment.unlink(); fragment.symlink_to(config)
                    if mutation == "empty": fragment.write_text("")
                    if mutation == "missing": fragment.unlink()
                    with self.subTest(mutation=mutation), self.assertRaises((ValueError, OSError)):
                        loader.docker_rules(str(fragment))
                os.chmod(root, 0o700)
                fragment.write_text(DOCKER)
                os.chmod(fragment, 0o600)
                policy = POLICY.replace('        counter drop\n    }\n    chain output',
                                        f'        include "{fragment}"\n        counter drop\n    }}\n    chain output')
                loader.nft("-f", "-", text="table ip foreign { chain sentinel { counter } }\n")
                foreign = loader.nft("-s", "list", "table", "ip", "foreign").stdout
                loader.activate(policy)
                live = loader.nft("-s", "list", "table", "inet", "hardening_filter").stdout
                for expected in ("tailscale0", "wg0", "2222", "11434", "docker0", "policy drop"):
                    self.assertIn(expected, live)
                self.check_source_boundary()
                config.write_text(policy)
                # Exercise the real persisted start/reload entry point as well
                # as direct candidate application. Invalid includes must retain
                # the active last-good policy and report the rejected reload.
                with patch.object(sys, "argv", ["helper"]):
                    loader.main()
                    for mutation in ("mode", "empty", "missing"):
                        fragment.write_text(DOCKER)
                        os.chmod(fragment, 0o600)
                        if mutation == "mode": os.chmod(fragment, 0o666)
                        if mutation == "empty": fragment.write_text("")
                        if mutation == "missing": fragment.unlink()
                        with self.subTest(reload=mutation), self.assertRaises((ValueError, OSError)):
                            loader.main()
                        self.assertEqual(live, loader.nft("-s", "list", "table", "inet", "hardening_filter").stdout)
                    fragment.write_text(DOCKER)
                    os.chmod(fragment, 0o600)
                    loader.main()
                self.assertEqual(live, loader.nft("-s", "list", "table", "inet", "hardening_filter").stdout)
                for bad in (policy.replace("ct state invalid drop", "invalid nft syntax"),
                            policy.replace(str(fragment), str(root / "missing")),
                            policy + "flush ruleset\n"):
                    with self.assertRaises((ValueError, OSError)):
                        loader.activate(bad)
                    self.assertEqual(live, loader.nft("-s", "list", "table", "inet", "hardening_filter").stdout)
                # A snapshot with counters suppressed can be restored atomically.
                loader.activate(live)
                self.assertEqual(live, loader.nft("-s", "list", "table", "inet", "hardening_filter").stdout)
                config.unlink()
                with patch.object(sys, "argv", ["helper"]), self.assertRaises(OSError):
                    loader.main()
                self.assertEqual(live, loader.nft("-s", "list", "table", "inet", "hardening_filter").stdout)
                # Simulate a fresh boot in this namespace only. Missing config
                # restores the self-contained last-good policy and reports failure.
                loader.nft("delete", "table", "inet", "hardening_filter")
                with patch.object(sys, "argv", ["helper"]), self.assertRaises(OSError):
                    loader.main()
                self.assertEqual(live, loader.nft("-s", "list", "table", "inet", "hardening_filter").stdout)
                self.assertEqual(foreign, loader.nft("-s", "list", "table", "ip", "foreign").stdout)
                # Real trust path must reject out-of-allowlist paths too.
                with self.assertRaises(ValueError): original_read(str(fragment))


if __name__ == "__main__":
    unittest.main(verbosity=2)
