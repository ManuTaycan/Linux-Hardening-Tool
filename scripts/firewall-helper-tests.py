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
        iifname "lo" accept
API_BOUNDARY
        ct state established,related accept
        meta l4proto ipv6-icmp accept
        iifname "tailscale0" accept comment "preserve Tailscale administration"
        udp dport 41641 accept
        iifname "wg0" accept
        tcp dport { 22, 2222 } ct state new accept
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
'''.replace('API_BOUNDARY', loader.api_rule('192.0.2.10', '11434'))
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
        self.assertIn('tcp dport 11434 counter drop', loader.api_rule("192.0.2.10", "11434"))
        shell = source[source.index("configure_firewall() {"):]
        self.assertLess(shell.index('${api_input}'), shell.index('ct state established,related accept'))
        self.assertLess(shell.index('${api_input}'), shell.index('${tailscale_input}'))
        self.assertLess(shell.index('iifname "lo" accept'), shell.index('${api_input}'))
        for address, port in (("", "443"), ("192.0.2.1", ""), ("0.0.0.0/0", "443"),
                             ("0.0.0.0", "443"), ("::", "443"), ("ff02::1", "443"),
                             ("fe80::1%lo", "443"), ("fe80::1%lo\naccept", "443"),
                             ("example.test", "443"), ("192.0.2.1", "65536"),
                             ("192.0.2.1; accept", "443"), ("192.0.2.1", "80; accept")):
            with self.subTest(source=address, port=port), self.assertRaises(ValueError):
                loader.api_rule(address, port)

    def test_persisted_api_selection(self):
        for source_ip in ("192.0.2.10", "2001:db8::10"):
            rules = loader.api_rule(source_ip, "11434")
            saved = POLICY.replace(loader.api_rule("192.0.2.10", "11434"), rules)
            with patch.object(loader.os.path, "lexists", return_value=True), patch.object(loader, "trusted_read", return_value=saved):
                self.assertEqual(loader.select_api("", "", "0", "22", "2222"), rules)
                self.assertEqual(loader.select_api("", "", "1", "22"), "")
                self.assertEqual(loader.select_api("192.0.2.20", "8443", "0", "22"), loader.api_rule("192.0.2.20", "8443"))
                for args in (("", "", "0", "11434"), ("", "443", "0"), ("192.0.2.1", "", "0"),
                             ("192.0.2.1", "443", "1"), ("", "", "2")):
                    with self.subTest(args=args), self.assertRaises(ValueError):
                        loader.select_api(*args)
            for bad in (saved.replace('source='+source_ip, 'source=invalid'),
                        saved.replace('counter drop comment "operator TCP source boundary"', 'counter accept'),
                        saved + rules):
                with patch.object(loader.os.path, "lexists", return_value=True), patch.object(loader, "trusted_read", return_value=bad), self.assertRaises(ValueError):
                    loader.select_api("", "", "0")
        with patch.object(loader.os.path, "lexists", return_value=False):
            self.assertEqual(loader.select_api("", "", "0", "22"), "")
        legacy = POLICY.replace(loader.api_rule("192.0.2.10", "11434"),
                                'ip saddr 192.0.2.10 tcp dport 11434 ct state new counter accept comment "operator TCP source exception"')
        with patch.object(loader.os.path, "lexists", return_value=True), patch.object(loader, "trusted_read", return_value=legacy):
            self.assertEqual(loader.select_api("", "", "0", "22"), loader.api_rule("192.0.2.10", "11434"))

    def test_docker_grammar(self):
        with patch.object(loader, "trusted_read", return_value=DOCKER):
            self.assertIn('dport { 53, 80, 443 }', loader.docker_rules("unused"))
        for bad in ("accept", DOCKER + "}; flush ruleset; {", DOCKER.replace("172.17.0.0/16", "0.0.0.0/0"),
                    DOCKER.replace("443", "65536"), DOCKER.replace('"docker0"', '"br-*"'),
                    'include "/etc/another.nft"', "# empty\n"):
            with self.subTest(bad=bad), patch.object(loader, "trusted_read", return_value=bad), self.assertRaises(ValueError):
                loader.docker_rules("unused")

    def test_persisted_docker_selection(self):
        configured = POLICY.replace('        counter drop\n    }\n    chain output',
                                    '        include "/etc/nftables.d/custom.rules"\n        counter drop\n    }\n    chain output')
        with patch.object(loader.os.path, "lexists", return_value=True), \
                patch.object(loader, "trusted_read", return_value=configured), \
                patch.object(loader, "docker_rules", return_value=DOCKER):
            self.assertEqual(loader.select_docker("", "0"), "/etc/nftables.d/custom.rules")
            self.assertEqual(loader.select_docker("", "1"), "")
            with patch.object(loader, "docker_rules", side_effect=FileNotFoundError("removed fragment")), self.assertRaises(OSError):
                loader.select_docker("", "0")
            with self.assertRaises(ValueError): loader.select_docker("/etc/nftables.d/custom.rules", "1")

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

    def check_source_boundary(self, policy):
        # Real TCP over disposable veths, including ingress named tailscale0
        # and wg0. This proves nft policy, not authenticated overlay services.
        peer = subprocess.Popen(["unshare", "--net", "sleep", "120"])
        servers = []
        current_name = "test-server"
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
            ip("link", "add", current_name, "type", "veth", "peer", "name", "test-client")
            ip("link", "set", "test-client", "netns", str(peer.pid))
            ip("addr", "add", "192.0.2.1/24", "dev", current_name)
            ip("addr", "add", "2001:db8::1/64", "dev", current_name, "nodad")
            ip("link", "set", current_name, "up")
            for address in ("192.0.2.10/24", "192.0.2.11/24", "2001:db8::10/64", "2001:db8::11/64"):
                args = ["ip", "addr", "add", address, "dev", "test-client"]
                if ":" in address: args += ["nodad"]
                subprocess.run(prefix + args, check=True)
            subprocess.run(prefix + ["ip", "link", "set", "test-client", "up"], check=True)
            for family, address in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
                for port in (11434, 2222):
                    server = socket.socket(family)
                    if family == socket.AF_INET6: server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    server.bind((address, port))
                    server.listen(128)
                    servers.append(server)
            client = ('import socket,sys; s=socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET); '
                      's.settimeout(0.5); s.bind((sys.argv[1],0)); s.connect((sys.argv[2],int(sys.argv[3])))')
            def connect(src, port=11434):
                dest = "2001:db8::1" if ":" in src else "192.0.2.1"
                return subprocess.run(prefix + [sys.executable, "-c", client, src, dest, str(port)], capture_output=True)
            for name in ("test-server", "tailscale0", "wg0"):
                if name != current_name:
                    ip("link", "set", current_name, "name", name)
                    current_name = name
                for trusted in ("192.0.2.10", "2001:db8::10"):
                    candidate = policy.replace(loader.api_rule("192.0.2.10", "11434"), loader.api_rule(trusted, "11434"))
                    loader.activate(candidate)
                    for src in ("192.0.2.10", "192.0.2.11", "2001:db8::10", "2001:db8::11"):
                        result = connect(src)
                        with self.subTest(interface=name, trusted=trusted, source=src):
                            self.assertEqual(result.returncode == 0, src == trusted, result.stderr)
                    for src in ("192.0.2.11", "2001:db8::11"):
                        self.assertEqual(connect(src, 2222).returncode, 0, "administrative SSH port blocked")
            # Unauthorized flow is established under general overlay access,
            # then denied even though conntrack still regards it as established.
            loader.activate(policy.replace(loader.api_rule("192.0.2.10", "11434"), ""))
            persistent = client + '; print("ready",flush=True); sys.stdin.readline(); s.sendall(b"forbidden"); sys.stdin.readline()'
            holder = subprocess.Popen(prefix + [sys.executable, "-c", persistent, "192.0.2.11", "192.0.2.1", "11434"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(holder.stdout.readline().strip(), "ready")
                # Drain earlier successful connections from the listener queue.
                servers[0].settimeout(0.2)
                accepted = []
                while True:
                    try: accepted.append(servers[0].accept()[0])
                    except socket.timeout: break
                loader.activate(policy)
                holder.stdin.write("send\n"); holder.stdin.flush()
                for conn in accepted:
                    conn.settimeout(0.5)
                    try: self.assertNotEqual(conn.recv(32), b"forbidden")
                    except socket.timeout: pass
                    finally: conn.close()
            finally:
                holder.terminate(); holder.communicate(timeout=5)
        finally:
            for server in servers: server.close()
            peer.terminate(); peer.wait(timeout=5)
            subprocess.run(["ip", "link", "delete", current_name], capture_output=True)
            loader.activate(policy)

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
                loader.nft("-f", "-", text="table ip foreign {\n chain sentinel {\n  counter\n }\n}\n")
                foreign = loader.nft("-s", "list", "table", "ip", "foreign").stdout
                loader.activate(policy)
                live = loader.nft("-s", "list", "table", "inet", "hardening_filter").stdout
                for expected in ("tailscale0", "wg0", "2222", "11434", "docker0", "policy drop"):
                    self.assertIn(expected, live)
                self.check_source_boundary(policy)
                config.write_text(policy)
                self.assertEqual(loader.select_docker("", "0"), str(fragment))
                self.assertEqual(loader.select_docker("", "1"), "")
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
                        with self.subTest(apply_selection=mutation), self.assertRaises((ValueError, OSError)):
                            loader.select_docker("", "0")
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
