# Lazarus

**Altsoftware in lesbaren, offenen Code zurückverwandeln — mit Nachweis.**

In Universitätslabors, Ämtern und Archiven stehen Geräte und Datenbestände, die von
Programmen abhängen, die niemand mehr pflegt. Das Messgerät funktioniert, aber seine
Software läuft nur auf einem alten Windows. Die Messreihen von zwanzig Jahren liegen in
einem Format, das nur dieses Programm lesen kann. Die Folge ist entweder ein unsicherer
Rechner, der nur deshalb weiterläuft, oder funktionierende Hardware auf dem Müll.

Die Fähigkeit, so ein Programm zu untersuchen und das Nötige neu zu schreiben, existiert.
Sie kostet nur Wochen Spezialarbeit pro Gerät — und findet deshalb nicht statt.

> **Stand: Prinzipbeweis.** Dieses Repository zeigt die Äquivalenzmaschinerie an einem
> nachgestellten Messdatenformat. Der produktive Teil — Eingrenzung über den Aufrufgraphen
> (Ghidra, angebunden über [`morluto/rea`](https://github.com/morluto/rea)),
> CPU-Emulation mit `unicorn`, Fuzzing mit `Hypothesis`, bottom-up-Synthese nach Rust,
> WebAssembly-Auslieferung — ist Gegenstand der Bewerbung beim Prototype Fund,
> Jahrgang 03.

## Ausprobieren

Keine Abhängigkeiten, Python 3.11 genügt:

```
python3 lazarus.py            # Vorführung
python3 lazarus.py --selftest # Tests
```

## Worum es wirklich geht

Dekompilierung ist das gelöste Problem. Ghidra kann das, und Lazarus baut dafür keinen
eigenen Decompiler. **Das Schwierige ist der Nachweis**, dass der neue offene Code
bitgenau dasselbe tut wie der alte — denn ein Formatleser, der in 99 Prozent der Fälle
stimmt, ist für ein Messdatenarchiv unbrauchbar.

Die Vorführung zeigt genau diesen Nachweis an einem Format mit den Eigenheiten, die
Laborgeräte tatsächlich haben: gepackte 12-bit-Werte, ein **vorzeichenbehafteter** Offset
im Kopf, eine XOR-Prüfsumme über den Kopf hinweg, und Rückgabe eines leeren Puffers statt
einer Ausnahme bei falscher Prüfsumme.

## Was die Vorführung zeigt

Ausgabe eines echten Durchlaufs (14.10.2026):

```
1) Verhalten der Altfunktion aufzeichnen
   2004 Eingabe-Ausgabe-Paare aufgezeichnet
   davon 1169 mit Ausgabe, 835 als ungültig zurückgewiesen
   Die Funktion wurde dabei nur aufgerufen, nicht gelesen.

2) Erster Nachbau gegen die Aufzeichnung
   1412 von 2004 (70.5 %) stimmen überein
   Gegenbeispiel: 3cdf9ee2dd42
     Original: 1b259b0a
     Nachbau:  1b269b0b
   Der Nachbau ist NICHT äquivalent — obwohl 70.5 Prozent der
   Fälle stimmen.

3) Nachbau korrigiert und erneut geprüft
   2004 von 2004 (100.0 %) stimmen überein
   äquivalent: JA
```

### Der Fehler, um den es geht

`nachbau_v1` liest den Offset im Kopf als **vorzeichenlos** statt vorzeichenbehaftet. Das
ist ein Zeichen Unterschied im Code, und es ist genau die Art Fehler, die eine
Dekompilierung produziert.

Die Folgen sind unauffällig: Bei jedem Block mit einem Offset unter 128 stimmt das Ergebnis,
und alle ungültigen Blöcke werden gleich zurückgewiesen. **70,5 Prozent der Fälle sind
korrekt.** Das Gegenbeispiel unterscheidet sich um **ein einziges Byte**: `1b259b0a` gegen
`1b269b0b`.

Bei einer Durchsicht wäre das nicht aufgefallen. In einem Messdatenarchiv hätte es stille,
systematische Verschiebungen über alle Dateien mit negativem Offset erzeugt — die Art
Fehler, die man erst Jahre später findet, wenn überhaupt.

### Warum das der entscheidende Teil ist

Die Aufzeichnung ist die Wahrheitstabelle. Die Altfunktion wird dabei **nur aufgerufen, nie
gelesen** — das ist zugleich die Clean-Room-Bedingung. Jede Abweichung liefert ein
**reproduzierbares Gegenbeispiel**, und das Gegenbeispiel ist die nächste Vorgabe für die
Synthese.

Fertig ist eine Funktion erst, wenn sie über alle aufgezeichneten Fälle bitgleich liefert.
Wo das nicht erreichbar ist — Gleitkomma, undefiniertes Verhalten —, wird die Abweichung
dokumentiert statt verschwiegen, und das Ziel ist dann nachgewiesene Äquivalenz im belegten
Eingaberaum.

Auch ein **Absturz** des Nachbaus zählt als Abweichung, nicht als Fehler des Prüfstands.

## Synergie: microG, libobscura, pd3f

- **[microG](https://www.prototypefund.de/projects/microg)** (Prototype Fund, Runde 5,
  14.860 Sterne, bis heute aktiv) hat die Google-Play-Dienste API-kompatibel nachgebaut und
  diese Rechtsposition über Jahre gehalten. Der Präzedenzfall dafür, dass
  PF-gefördertes Clean-Room-Engineering langfristig trägt.
- **[libobscura](https://www.prototypefund.de/projects/libobscura)** (Runde 16) löst
  dasselbe Handwerksproblem für Kamera-Blobs auf Linux-Telefonen — erprobte
  Workflow-Vorlage, samt
  [38C3-Vortrag](https://media.ccc.de/v/38c3-libobscura-cameras-are-difficult) als
  Methodendokumentation.
- **[pd3f](https://www.prototypefund.de/projects/ddd-deutsche-dokumente-digitalisieren)**
  (Runde 7, 335 Sterne) extrahiert Fließtext aus Dokumenten — die natürliche
  Weiterverarbeitung befreiter Altdateien. **Seit Oktober 2023 ohne Commit**, also ein
  konkreter Kandidat für eine Wartungsübernahme.

## Herkunft

Ich arbeite seit 2021 am GeoZentrum Nordbayern der FAU Erlangen-Nürnberg mit Messdaten aus
Geräten, deren Ausgabeformate nirgends dokumentiert sind, und habe mehr als einmal eine
Spalte verstanden, indem ich ihre Zahlen gegen bekannte Werte hielt. Das ist die Arbeit,
die Lazarus automatisieren soll, nur von Hand.

## Lizenz

Apache-2.0 — siehe [LICENSE](LICENSE).
