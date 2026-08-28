# Release-Ablauf

Vor einem Release:

1. Zielsystemtest erfolgreich abschließen.
2. Offene Findings und ihre Risikoabwägung prüfen.
3. Version und Changelog aktualisieren.
4. `SHA256SUMS` neu erzeugen und prüfen.
5. CI grün abwarten.
6. Tag erstellen.
7. GitHub Release erstellen.
8. Download über den gepinnten Tag mit `install.sh --ref TAG` testen.

Für 1.1.3 wird jetzt weder ein Tag noch ein GitHub Release erzeugt. Das erfolgt
erst nach dem realen Ubuntu-26.04.1-Test.
