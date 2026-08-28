# Contributing

Arbeite mit einem Branch und einem Pull Request. Ein Issue beschreibt genau ein
Problem; ein Pull Request bleibt ein klar begrenztes Arbeitspaket.

Jede Änderung an `harden.sh` benötigt nachvollziehbare Testnachweise,
idempotentes Verhalten und einen dokumentierten Rollback-Pfad. Keine Änderung
darf ausschließlich der kosmetischen Erhöhung eines Lynis-Scores dienen.

Ändere weder die SSH-Port- noch die GRUB-Passwort-Policy ohne ausdrückliche
Projektentscheidung. Bash-Code muss mit `set -Eeuo pipefail` kompatibel sein,
Eingaben quoten, temporäre Dateien bereinigen und Fehlerpfade sichtbar machen.
Führe vor einem PR mindestens `make check` aus und füge keine Secrets oder
unbereinigten Produktionslogs hinzu.
