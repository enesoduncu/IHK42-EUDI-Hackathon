#!/usr/bin/env python3
"""
Generator fuer ein IHK-Pruefungszeugnis als SD-JWT VC (PuB-EAA).

Erzeugt ein ECHTES, ES256-signiertes SD-JWT VC mit echten Disclosure-Digests.
Nur stdlib + 'cryptography'. Keine externen JWT-Libs noetig.

vct: urn:eudi:ihk:examcert:1   (analog zum deutschen PID 'urn:eudi:pid:de:1')

Selektiv offenlegbar (_sd): alle personen-/leistungsbezogenen Daten.
Immer sichtbar: vct, iss, iat, exp, cnf, _sd_alg + Aussteller-Metadaten.
"""

import json, os, hashlib, base64, secrets, datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# ---------- base64url helpers ----------
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def jwt_segment(obj) -> str:
    return b64u(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

# ---------- SD-JWT disclosure mechanics ----------
def make_disclosure(claim_name: str, claim_value) -> tuple[str, str]:
    """Returns (disclosure_b64u, digest_b64u). Disclosure = [salt, name, value]."""
    salt = b64u(secrets.token_bytes(16))
    arr = [salt, claim_name, claim_value]
    disclosure = b64u(json.dumps(arr, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    digest = b64u(hashlib.sha256(disclosure.encode("ascii")).digest())
    return disclosure, digest

# ---------- ES256 signing (JWS raw R||S) ----------
def es256_sign(signing_input: bytes, priv: ec.EllipticCurvePrivateKey) -> str:
    der = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return b64u(raw)

def public_jwk(pub: ec.EllipticCurvePublicKey) -> dict:
    nums = pub.public_numbers()
    return {
        "kty": "EC", "crv": "P-256",
        "x": b64u(nums.x.to_bytes(32, "big")),
        "y": b64u(nums.y.to_bytes(32, "big")),
    }

# ---------- Keys ----------
issuer_key = ec.generate_private_key(ec.SECP256R1())   # IHK signing key (LoA: would be HSM in prod)
holder_key = ec.generate_private_key(ec.SECP256R1())   # Wallet key binding

# ---------- Zeugnis-Daten (Beispiel: Erika Mustermann) ----------
now = datetime.datetime(2026, 6, 3, tzinfo=datetime.timezone.utc)
exp = now.replace(year=now.year + 5)   # 5 Jahre, analog PAuswG-Logik fuer PID

# Selektiv offenlegbare Claims (name -> value)
sd_claims = {
    "family_name": "MUSTERMANN",
    "given_name": "ERIKA",
    "birthdate": "1999-08-12",
    "place_of_birth": {"locality": "STUTTGART"},
    # Abschluss 
    "occupation": "KAUFMANN/-FRAU FUER DIGITALISIERUNGSMANAGEMENT",
    "qualification": {
        "title": "ABSCHLUSSPRUEFUNG TEIL 2",
        "specialization": None,        # ggf. Fachrichtung
        "legal_basis": "§ 37 ABS. 2 BBIG",
    },
    # Einzelne Pruefungsbereiche (ganzes Array als 1 SD-Claim; pro-Bereich-SD ist auch moeglich)
    "grades": [
        {"area": "ENTWICKELN UND BEREITSTELLEN VON IT-LOESUNGEN", "grade": "GUT", "points": 84},
        {"area": "PLANEN EINES SOFTWAREPROJEKTES",               "grade": "SEHR GUT", "points": 92},
        {"area": "WIRTSCHAFTS- UND SOZIALKUNDE",                 "grade": "BEFRIEDIGEND", "points": 71},
    ],
    "overall_result": {"grade": "GUT", "points": 83},
    "vocational_school_grade": "GUT",   # nur auf Wunsch
}

# Immer sichtbare Claims (Aussteller-Metadaten, nicht SD)
clear_claims = {
    "issuing_authority": "IHK REGION STUTTGART",
    "issuing_country": "DE",
    "issuance_date": now.date().isoformat(),
    "status": {"status_list": {"idx": 0, "uri": "https://ihk.example/statuslists/examcert/1"}},
}

# ---------- Build SD-JWT payload ----------
disclosures = []
sd_digests = []
for name, value in sd_claims.items():
    d, digest = make_disclosure(name, value)
    disclosures.append((name, value, d))
    sd_digests.append(digest)

payload = {
    "vct": "urn:eudi:ihk:examcert:1",
    "iss": "https://ihk.example/issuer",
    "iat": int(now.timestamp()),
    "exp": int(exp.timestamp()),
    "_sd_alg": "sha-256",
    "_sd": sorted(sd_digests),                 # sorted per SD-JWT spec
    "cnf": {"jwk": public_jwk(holder_key.public_key())},
    **clear_claims,
}

header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "ihk-examcert-2026"}
signing_input = f"{jwt_segment(header)}.{jwt_segment(payload)}".encode("ascii")
signature = es256_sign(signing_input, issuer_key)
issuer_jwt = f"{signing_input.decode('ascii')}.{signature}"

# Compact SD-JWT VC serialization: <JWT>~<D1>~<D2>~...~  (trailing ~, no KB-JWT here)
sd_jwt_vc = issuer_jwt + "~" + "~".join(d for _, _, d in disclosures) + "~"

# ---------- Output ----------
print("=" * 70)
print("IHK-PRUEFUNGSZEUGNIS  ->  SD-JWT VC  (vct: urn:eudi:ihk:examcert:1)")
print("=" * 70)

print("\n--- 1) JWT HEADER (decoded) ---")
print(json.dumps(header, indent=2, ensure_ascii=False))

print("\n--- 2) JWT PAYLOAD (decoded, what the IHK signs) ---")
print(json.dumps(payload, indent=2, ensure_ascii=False))

print("\n--- 3) DISCLOSURES (decoded [salt, name, value]) ---")
for name, value, d in disclosures:
    raw = base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)).decode("utf-8")
    print(f"  {name:24s} -> {raw}")

print("\n--- 4) COMPACT SD-JWT VC (this goes into the wallet) ---")
print(sd_jwt_vc)

print("\n--- 5) SELEKTIVE OFFENLEGUNG: nur 'occupation' + 'overall_result' zeigen ---")
keep = {"occupation", "overall_result"}
presented = issuer_jwt + "~" + "~".join(d for n, _, d in disclosures if n in keep) + "~"
print(presented)
print("  -> Verifier sieht: Beruf + Gesamtergebnis. NICHT: Name, Geburtsdatum, Einzelnoten.")
print("  -> Genau das, was Cert4Trust (PDF-Hash) NICHT kann.\n")
