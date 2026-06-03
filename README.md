# IHK42-EUDI-Hackathon
# IHK-Prüfungszeugnis als EUDI-Credential — Datenmodell & Mapping

**Zweck:** Referenz-Datenmodell für die Ausstellung eines IHK-Prüfungszeugnisses
als EUDI-Attestation (PuB-EAA) im Hackathon. Format primär **SD-JWT VC**,
sekundär **mdoc (ISO/IEC 18013-5)**. Protokoll: **OpenID4VCI 1.0**.

---

## 1. Einordnung: Was ist das hier (und was nicht)

| | PID | IHK-Prüfungszeugnis |
|---|---|---|
| Was | "Wer bist du" (Identität) | Aussage über eine Person (Qualifikation) |
| EUDI-Klasse | PID | **PuB-EAA** (Public-Body EAA) |
| Aussteller | 1 PID-Provider DE | IHK als zuständige Stelle (§ 71 BBiG, Prüfungsausschuss = Organ der IHK) |
| Rechtsgrundlage Zeugnis | PAuswG | § 37 Abs. 2 BBiG, § 27 Prüfungsordnung |

Die IHK ist eine Körperschaft des öffentlichen Rechts und stellt das Zeugnis
hoheitlich aus → die Attestation fällt sauber in die Klasse **pubeaa**, die der
EUDI-Verifier (`eudi-srv-verifier-endpoint`) ohnehin kennt (Klassen: pid / qeaa / pubeaa).

---

## 2. vct (Verifiable Credential Type)

```
urn:eudi:ihk:examcert:1
```

Analog zum deutschen PID (`urn:eudi:pid:de:1`). Die "1" kodiert die Version;
ein späteres `:2` erlaubt parallele Versionen (SD-JWT-VC-Konvention).

---

## 3. Claim-Modell

`SD` = selektiv offenlegbar (Holder entscheidet pro Präsentation).
`clear` = immer sichtbar (Aussteller-Metadaten, technisch nicht verbergbar).

| Zeugnis-Feld | Claim | Typ | Sichtbarkeit |
|---|---|---|---|
| Familienname | `family_name` | string | SD |
| Vorname(n) | `given_name` | string | SD |
| Geburtsdatum | `birthdate` | string (YYYY-MM-DD) | SD |
| Geburtsort | `place_of_birth` | object `{locality}` | SD |
| Ausbildungsberuf | `occupation` | string | SD |
| Abschluss/Fachrichtung/Rechtsbasis | `qualification` | object `{title, specialization, legal_basis}` | SD |
| Prüfungsbereiche + Noten | `grades` | array `[{area, grade, points}]` | SD (ganzes Array) |
| Gesamtergebnis | `overall_result` | object `{grade, points}` | SD |
| Berufsschulnote (auf Wunsch) | `vocational_school_grade` | string | SD |
| Ausstellende IHK | `issuing_authority` | string | clear |
| Ausstellerland | `issuing_country` | string ("DE") | clear |
| Ausstellungsdatum | `issuance_date` | string (YYYY-MM-DD) | clear |
| Widerrufsstatus | `status` | object (IETF Token Status List) | clear |
| Typ | `vct` | string | clear |
| Aussteller | `iss` | string (URL) | clear |
| Gültig ab / bis | `iat` / `exp` | int (Unix) | clear |
| Schlüsselbindung Wallet | `cnf.jwk` | object | clear |

> **Pitch-Tipp:** `grades` lässt sich auch pro Prüfungsbereich einzeln
> offenlegbar machen (array-element-SD). Für eine Demo reicht das ganze Array;
> "pro Note einzeln" ist aber ein starkes Folge-Argument für selektive Offenlegung.

---

## 4. Beispiel — SD-JWT VC Payload (das, was die IHK signiert)

```json
{
  "vct": "urn:eudi:ihk:examcert:1",
  "iss": "https://ihk.example/issuer",
  "iat": 1780444800,
  "exp": 1938211200,
  "_sd_alg": "sha-256",
  "_sd": [ "<digest>", "<digest>", "..." ],
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } },
  "issuing_authority": "IHK REGION STUTTGART",
  "issuing_country": "DE",
  "issuance_date": "2026-06-03",
  "status": { "status_list": { "idx": 0, "uri": "https://ihk.example/statuslists/examcert/1" } }
}
```

Die SD-Claims stehen **nicht** im Payload, sondern als separate *Disclosures*
(`[salt, name, value]`), deren SHA-256-Digests im `_sd`-Array liegen. Beispiel
einer dekodierten Disclosure:

```
["q4RjkaDNQT_H7CylucPtWw", "family_name", "MUSTERMANN"]
```

Ein komplettes, **echt signiertes** Beispiel erzeugt `generate_ihk_examcert_sdjwt.py`
(ES256, echte Digests). Header-`typ`: `dc+sd-jwt` (aktueller Draft; ältere Stände: `vc+sd-jwt`).

> **Header-Konvention:** Strings folgen dem deutschen PID-Rulebook → **UPPERCASE**,
> Umlaute bleiben erhalten ("KÖLN", nicht "KOELN"). Geburtsdatum darf laut PID-DE
> unvollständig sein ("1999-00-00"), falls Tag/Monat fehlen.

---

## 5. mdoc-Variante (ISO/IEC 18013-5) — sekundär

- **doctype (Vorschlag):** `eu.europa.ec.eudi.ihk.examcert.1`
- **namespace:** gleichnamig; deutsche/IHK-spezifische Felder analog zum
  PID-Muster (`eu.europa.ec.eudi.pid.de.1`).
- Jedes Element als `{digestID, random, elementIdentifier, elementValue}`,
  signiert über die MSO (Mobile Security Object) im `issuerAuth`.
- Beide Referenz-Issuer können mdoc **und** SD-JWT VC — du kannst beide demoen.

---

## 6. OpenID4VCI — Credential Request

Beispiel-Request an den Credential-Endpoint des Issuers (SD-JWT VC):

```http
POST {credential_endpoint}
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "format": "dc+sd-jwt",
  "vct": "urn:eudi:ihk:examcert:1",
  "proof": { "proof_type": "jwt", "jwt": "<wallet-key-proof>" }
}
```

mdoc-Variante: `"format": "mso_mdoc"`, `"doctype": "eu.europa.ec.eudi.ihk.examcert.1"`.

---

## 7. Anbindung an die EUDI-Referenz-Implementierung

Zwei nutzbare Issuer (beide Apache-2.0, beide mdoc + SD-JWT VC):

- **`eudi-srv-web-issuing-eudiw-py`** (Python) — PID **+ (Q)EAA**-Provider,
  OID4VCI 1.0, gehostete Demo `issuer.eudiw.dev`, "simple form"-Auth zum Testen
  (kein echter eIDAS-Node nötig). → **Empfehlung für den Hackathon.**
- **`eudi-srv-pid-issuer`** (Kotlin) — bringt PID, mDL, EHIC und ein
  **Learning Credential** als Beispiel mit; docker-compose + Keycloak.
  → Gutes Vorbild, weil "Learning Credential" dem Zeugnis am nächsten ist.

**Praktischer Weg:** Learning-Credential- bzw. (Q)EAA-Beispiel kopieren,
Credential-Config mit unserem `vct`, den Claims aus §3 und der
Issuer-Metadata-Display füllen, neuen Scope/`credential_configuration_id`
definieren. Verifikation gegen `eudi-srv-verifier-endpoint`
(`VERIFIER_ATTESTATIONCLASSIFICATIONS` → Klasse `pubeaa`, vct eintragen).

---

## 8. Lebenszyklus

- **Gültigkeit:** Vorschlag 5 Jahre (`exp`), analog zur PID-Logik. Ein Zeugnis
  ist inhaltlich unveränderlich — bei Namensänderung wird **nicht** erneuert,
  sondern neu ausgestellt.
- **Widerruf:** über IETF Token Status List (`status`-Claim), z. B. bei
  Rücknahme/Ungültigkeit.
