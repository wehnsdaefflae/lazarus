"""lazarus — Prinzipbeweis: Äquivalenz nachweisen, nicht behaupten.

In Universitätslabors und Ämtern stehen Geräte, deren Software nur auf einem alten Windows
läuft, und Messreihen in Formaten, die nur ein eingestelltes Programm lesen kann. Die
Fähigkeit, so ein Programm zu untersuchen und das Nötige neu zu schreiben, existiert — sie
kostet nur Wochen Spezialarbeit pro Gerät und findet deshalb nicht statt.

Der Teil, der Lazarus eigenständig macht, ist nicht die Dekompilierung (dafür gibt es
Ghidra, angebunden über `morluto/rea`). Es ist der **Nachweis**: dass der neue offene Code
bitgenau dasselbe tut wie der alte.

Dieses Modul zeigt diese Maschinerie an einem kleinen, aber echten Fall: einem
Messdatenformat mit 12-bit-Rohwerten, Kalibrierung und einer Prüfsumme — der Art von
Format, das in Laborgeräten tatsächlich steckt.

* `altfunktion` steht für die Routine im geschlossenen Binary. Sie wird nur **beobachtet**,
  nie gelesen: der Prüfstand ruft sie auf und zeichnet Eingabe und Ausgabe auf.
* `nachbau_v1` ist der erste Versuch — er ist **falsch**, und der Prüfstand findet das
  Gegenbeispiel.
* `nachbau_v2` entsteht aus dem Gegenbeispiel und besteht.

Ausführen:   python3 lazarus.py
Tests:       python3 lazarus.py --selftest
"""

from __future__ import annotations

import random
import struct
import sys
from dataclasses import dataclass
from typing import Callable

# --- Die "Altfunktion". Steht hier für eine Routine im geschlossenen Binary, die
#     im echten Fall nur über den Emulator beobachtet würde. --------------------------


def altfunktion(roh: bytes) -> bytes:
    """Dekodiert einen Messblock: 2 Byte Kopf, dann 12-bit-Werte, 1 Byte Prüfsumme.

    Eigenheiten, wie sie in echten Formaten vorkommen und die man einem Nachbau
    nicht ansieht:
      * die 12-bit-Werte sind gepackt (zwei Werte in drei Byte),
      * der Offset im Kopf ist vorzeichenbehaftet (int8),
      * die Prüfsumme ist eine XOR-Summe ÜBER DEN KOPF HINWEG,
      * bei falscher Prüfsumme liefert die Funktion b"" statt einer Ausnahme.
    """
    if len(roh) < 3:
        return b""

    faktor = roh[0]
    offset = struct.unpack("b", roh[1:2])[0]   # vorzeichenbehaftet!
    nutz = roh[2:-1]
    pruef = roh[-1]

    xor = 0
    for b in roh[:-1]:                          # Kopf eingeschlossen
        xor ^= b
    if xor != pruef:
        return b""

    werte: list[int] = []
    i = 0
    while i + 2 < len(nutz) + 1 and i + 3 <= len(nutz):
        a, b, c = nutz[i], nutz[i + 1], nutz[i + 2]
        werte.append(((a << 4) | (b >> 4)) & 0xFFF)
        werte.append((((b & 0x0F) << 8) | c) & 0xFFF)
        i += 3

    aus = bytearray()
    for w in werte:
        skaliert = (w * faktor) // 16 + offset
        aus += struct.pack("<h", max(-32768, min(32767, skaliert)))
    return bytes(aus)


# --- Der Prüfstand. ----------------------------------------------------------------


@dataclass(frozen=True)
class Paar:
    eingabe: bytes
    ausgabe: bytes


def _gueltiger_block(rng: random.Random, n_tripel: int = 2) -> bytes:
    """Baut einen Block mit korrekter Prüfsumme — sonst prüft man nur den Fehlerpfad."""
    kopf = bytes([rng.randrange(1, 64), rng.randrange(0, 256)])
    nutz = bytes(rng.randrange(0, 256) for _ in range(3 * n_tripel))
    xor = 0
    for b in kopf + nutz:
        xor ^= b
    return kopf + nutz + bytes([xor])


def zeichne_auf(f: Callable[[bytes], bytes], anzahl: int = 2000,
                seed: int = 20261014) -> list[Paar]:
    """Zeichnet Eingabe-Ausgabe-Paare auf — die Wahrheitstabelle des Nachbaus.

    Mischung aus gültigen Blöcken, kaputten Prüfsummen, Grenzfällen und Müll.
    Das entspricht dem eigenschaftsbasierten Fuzzing mit `Hypothesis` im Entwurf.
    """
    rng = random.Random(seed)
    paare: list[Paar] = []

    for fall in (b"", b"\x00", b"\x01\x02", b"\x00\x00\x00"):
        paare.append(Paar(fall, f(fall)))

    for _ in range(anzahl):
        w = rng.random()
        if w < 0.6:
            e = _gueltiger_block(rng, rng.randrange(1, 4))
        elif w < 0.8:
            e = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(3, 12)))
        else:
            e = _gueltiger_block(rng, 1)
            e = e[:-1] + bytes([(e[-1] + 1) & 0xFF])     # Prüfsumme kaputt
        paare.append(Paar(e, f(e)))

    return paare


@dataclass
class Ergebnis:
    bestanden: int
    gescheitert: int
    gegenbeispiel: Paar | None
    war: bytes | None

    @property
    def aequivalent(self) -> bool:
        return self.gescheitert == 0

    @property
    def quote(self) -> float:
        gesamt = self.bestanden + self.gescheitert
        return 100.0 * self.bestanden / gesamt if gesamt else 0.0


def pruefe_aequivalenz(nachbau: Callable[[bytes], bytes],
                       paare: list[Paar]) -> Ergebnis:
    """Vergleicht den Nachbau mit der Aufzeichnung — bitweise, nicht ungefähr."""
    bestanden = gescheitert = 0
    erstes: Paar | None = None
    war: bytes | None = None

    for p in paare:
        try:
            got = nachbau(p.eingabe)
        except Exception as e:                   # ein Absturz ist auch eine Abweichung
            got = f"<Absturz: {e}>".encode()
        if got == p.ausgabe:
            bestanden += 1
        else:
            gescheitert += 1
            if erstes is None:
                erstes, war = p, got

    return Ergebnis(bestanden, gescheitert, erstes, war)


# --- Zwei Nachbauten: der erste scheitert, der zweite besteht. ---------------------


def nachbau_v1(roh: bytes) -> bytes:
    """Erster Versuch. EIN Fehler, den man dem Pseudocode nicht ansieht: der Offset
    im Kopf wird als vorzeichenlos gelesen.

    Genau das ist der gefährliche Fall. Bei jedem Block mit Offset unter 128 stimmt
    das Ergebnis, und alle ungültigen Blöcke werden gleich zurückgewiesen — der
    Nachbau stimmt deshalb in der grossen Mehrheit der Fälle und fällt bei einer
    Durchsicht nicht auf.
    """
    if len(roh) < 3:
        return b""

    faktor = roh[0]
    offset = roh[1]                      # FALSCH: unsigned statt signed
    nutz = roh[2:-1]
    pruef = roh[-1]

    xor = 0
    for b in roh[:-1]:
        xor ^= b
    if xor != pruef:
        return b""

    werte: list[int] = []
    i = 0
    while i + 3 <= len(nutz):
        a, b, c = nutz[i], nutz[i + 1], nutz[i + 2]
        werte.append(((a << 4) | (b >> 4)) & 0xFFF)
        werte.append((((b & 0x0F) << 8) | c) & 0xFFF)
        i += 3

    aus = bytearray()
    for w in werte:
        aus += struct.pack("<h", max(-32768, min(32767, (w * faktor) // 16 + offset)))
    return bytes(aus)


def nachbau_v2(roh: bytes) -> bytes:
    """Aus dem Gegenbeispiel korrigiert: der Offset wird vorzeichenbehaftet gelesen."""
    if len(roh) < 3:
        return b""

    faktor = roh[0]
    offset = struct.unpack("b", roh[1:2])[0]
    nutz = roh[2:-1]
    pruef = roh[-1]

    xor = 0
    for b in roh[:-1]:
        xor ^= b
    if xor != pruef:
        return b""

    werte: list[int] = []
    i = 0
    while i + 3 <= len(nutz):
        a, b, c = nutz[i], nutz[i + 1], nutz[i + 2]
        werte.append(((a << 4) | (b >> 4)) & 0xFFF)
        werte.append((((b & 0x0F) << 8) | c) & 0xFFF)
        i += 3

    aus = bytearray()
    for w in werte:
        skaliert = (w * faktor) // 16 + offset
        aus += struct.pack("<h", max(-32768, min(32767, skaliert)))
    return bytes(aus)


def vorfuehrung() -> int:
    print("1) Verhalten der Altfunktion aufzeichnen")
    paare = zeichne_auf(altfunktion)
    mit_ausgabe = sum(1 for p in paare if p.ausgabe)
    print(f"   {len(paare)} Eingabe-Ausgabe-Paare aufgezeichnet")
    print(f"   davon {mit_ausgabe} mit Ausgabe, "
          f"{len(paare) - mit_ausgabe} als ungültig zurückgewiesen")
    print("   Die Funktion wurde dabei nur aufgerufen, nicht gelesen.")
    print()

    print("2) Erster Nachbau gegen die Aufzeichnung")
    e1 = pruefe_aequivalenz(nachbau_v1, paare)
    print(f"   {e1.bestanden} von {len(paare)} ({e1.quote:.1f} %) stimmen überein")
    if e1.gegenbeispiel:
        g = e1.gegenbeispiel
        print(f"   Gegenbeispiel: {g.eingabe.hex()}")
        print(f"     Original: {g.ausgabe.hex() or '(leer)'}")
        print(f"     Nachbau:  {(e1.war or b'').hex() or '(leer)'}")
    print(f"   Der Nachbau ist NICHT äquivalent — obwohl {e1.quote:.1f} Prozent der")
    print("   Fälle stimmen. Genau deshalb braucht es den Nachweis: bei einer")
    print("   Durchsicht wäre dieser Fehler nicht aufgefallen.")
    print()

    print("3) Nachbau korrigiert und erneut geprüft")
    e2 = pruefe_aequivalenz(nachbau_v2, paare)
    print(f"   {e2.bestanden} von {len(paare)} ({e2.quote:.1f} %) stimmen überein")
    print(f"   äquivalent: {'JA' if e2.aequivalent else 'NEIN'}")
    print()
    print("   Das ist der Nachweis, den Lazarus liefern soll: nicht 'sieht richtig")
    print("   aus', sondern bitgleich über den belegten Eingaberaum — und wo das")
    print("   nicht erreichbar ist, wird die Abweichung dokumentiert.")
    return 0 if e2.aequivalent and not e1.aequivalent else 1


def selftest() -> int:
    ok = True

    def expect(c: bool, m: str) -> None:
        nonlocal ok
        if not c:
            ok = False
            print(f"FAIL: {m}", file=sys.stderr)

    paare = zeichne_auf(altfunktion, anzahl=1500)
    expect(len(paare) == 1504, f"Aufzeichnung vollständig, waren {len(paare)}")
    expect(any(p.ausgabe for p in paare), "es gibt gültige Blöcke mit Ausgabe")
    expect(any(not p.ausgabe for p in paare), "es gibt zurückgewiesene Blöcke")

    # Die Funktion ist deterministisch — sonst wäre der ganze Ansatz sinnlos.
    expect(all(altfunktion(p.eingabe) == p.ausgabe for p in paare),
           "die Altfunktion ist deterministisch")

    e1 = pruefe_aequivalenz(nachbau_v1, paare)
    expect(not e1.aequivalent, "der erste Nachbau wird als abweichend erkannt")
    expect(e1.gegenbeispiel is not None, "ein Gegenbeispiel wird benannt")
    expect(e1.quote > 50.0, "der falsche Nachbau stimmt in der Mehrheit der Fälle "
                            "— genau deshalb braucht es den Test")

    e2 = pruefe_aequivalenz(nachbau_v2, paare)
    expect(e2.aequivalent, f"der korrigierte Nachbau ist äquivalent "
                           f"({e2.gescheitert} Abweichungen)")
    expect(e2.gegenbeispiel is None, "kein Gegenbeispiel mehr")
    expect(e2.quote == 100.0, "100 Prozent Übereinstimmung")

    # Das Gegenbeispiel muss reproduzierbar sein, sonst ist es als Vorgabe nutzlos.
    g = e1.gegenbeispiel
    assert g is not None
    expect(nachbau_v1(g.eingabe) != altfunktion(g.eingabe),
           "das Gegenbeispiel ist reproduzierbar")
    expect(nachbau_v2(g.eingabe) == altfunktion(g.eingabe),
           "die Korrektur behebt genau dieses Gegenbeispiel")

    # Ein abstürzender Nachbau gilt als Abweichung, nicht als Fehler des Prüfstands.
    def kaputt(_: bytes) -> bytes:
        raise RuntimeError("boom")

    e3 = pruefe_aequivalenz(kaputt, paare[:10])
    expect(not e3.aequivalent and e3.gescheitert > 0,
           "ein Absturz zählt als Abweichung")

    # Signed/unsigned: der Fall, der v1 zu Fall bringt, wird wirklich erzeugt
    expect(any(p.eingabe[1:2] and p.eingabe[1] > 127
               for p in paare if len(p.eingabe) > 1),
           "negative Offsets kommen in der Aufzeichnung vor")

    # Dieselbe Aufzeichnung ist bei gleichem Seed reproduzierbar
    expect([p.eingabe for p in zeichne_auf(altfunktion, 50, seed=7)]
           == [p.eingabe for p in zeichne_auf(altfunktion, 50, seed=7)],
           "die Aufzeichnung ist mit Seed reproduzierbar")

    print("selftest: PASS" if ok else "selftest: FAIL", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else vorfuehrung())
