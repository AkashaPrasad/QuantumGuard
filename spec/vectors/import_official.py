"""Extract the ML-KEM-768, ML-DSA-65 and X-Wing known-answer vectors used by QG-1.

Inputs (downloaded by hand, never at test time):
  ACVP-Server gen-val/json-files/{ML-KEM-keyGen-FIPS203,ML-KEM-encapDecap-FIPS203,
      ML-DSA-keyGen-FIPS204,ML-DSA-sigVer-FIPS204}/internalProjection.json
  C2SP/wycheproof testvectors_v1/mlkem_768_test.json
  draft-connolly-cfrg-xwing-kem-11.txt (Appendix C)

Usage: python spec/vectors/import_official.py <download_dir>
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent


def load(d: Path, name: str) -> dict:
    return json.loads((d / f"{name}.json").read_text())


def mlkem(d: Path) -> dict:
    kg = load(d, "ML-KEM-keyGen-FIPS203")
    keygen = [
        {"tcId": t["tcId"], "d": t["d"].lower(), "z": t["z"].lower(), "ek": t["ek"].lower(), "dk": t["dk"].lower()}
        for g in kg["testGroups"]
        if g["parameterSet"] == "ML-KEM-768"
        for t in g["tests"]
    ]
    wp = json.loads((d / "mlkem_768_test.json").read_text())
    decaps = [
        {
            "tcId": t["tcId"],
            "source": g["source"]["name"],
            "comment": t.get("comment", ""),
            "seed": t["seed"],
            "ek": t.get("ek", ""),
            "c": t.get("c", ""),
            "k": t.get("K", ""),
            "result": t["result"],
        }
        for g in wp["testGroups"]
        for t in g["tests"]
    ]
    return {
        "algorithm": "ML-KEM-768",
        "sources": {
            "keygen": f"NIST ACVP-Server ML-KEM-keyGen-FIPS203 internalProjection.json (vsId {kg['vsId']}), group ML-KEM-768",
            "decaps": "C2SP/wycheproof testvectors_v1/mlkem_768_test.json (seed = d || z, ek, c, K, result); "
            "result invalid means the seed or ciphertext must be rejected",
        },
        "notes": "Seed for libraries taking 64 bytes is d || z. Implicit rejection check: flipping any byte of c "
        "must yield SHAKE256(z || c', 32 bytes) (FIPS 203 Algorithm 18, J function).",
        "keygen": keygen,
        "decaps": decaps,
    }


def mldsa(d: Path) -> dict:
    kg = load(d, "ML-DSA-keyGen-FIPS204")
    sv = load(d, "ML-DSA-sigVer-FIPS204")
    keygen = [
        {"tcId": t["tcId"], "seed": t["seed"].lower(), "pk": t["pk"].lower()}
        for g in kg["testGroups"]
        if g["parameterSet"] == "ML-DSA-65"
        for t in g["tests"]
    ]
    sigver = [
        {
            "tcId": t["tcId"],
            "pk": t["pk"].lower(),
            "message": t["message"].lower(),
            "context": t["context"].lower(),
            "signature": t["signature"].lower(),
            "testPassed": t["testPassed"],
        }
        for g in sv["testGroups"]
        if g["parameterSet"] == "ML-DSA-65"
        and g["signatureInterface"] == "external"
        and g["preHash"] == "pure"
        and not g.get("externalMu")
        for t in g["tests"]
    ]
    return {
        "algorithm": "ML-DSA-65",
        "sources": {
            "keygen": f"NIST ACVP-Server ML-DSA-keyGen-FIPS204 internalProjection.json (vsId {kg['vsId']}), group ML-DSA-65",
            "sigver": f"NIST ACVP-Server ML-DSA-sigVer-FIPS204 internalProjection.json (vsId {sv['vsId']}), "
            "group ML-DSA-65 external pure",
        },
        "keygen": keygen,
        "sigver": sigver,
    }


def xwing(d: Path) -> dict:
    lines = (d / "draft-connolly-cfrg-xwing-kem-11.txt").read_text().splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("Appendix C."))
    vecs: list[dict] = []
    key = None
    for ln in lines[start + 2 :]:
        if ln.startswith("Appendix D."):
            break
        if ln.startswith(("Connolly", "Internet-Draft")) or not ln.strip():
            continue
        m = re.match(r"^([a-z]+)\s*([0-9a-f]*)\s*$", ln)
        if m:
            key = m.group(1)
            if key == "seed":
                vecs.append({})
            vecs[-1][key] = m.group(2)
        elif re.match(r"^\s+[0-9a-f]+\s*$", ln) and key:
            vecs[-1][key] += ln.strip()
    out = [{"seed": v["seed"], "pk": v["pk"], "eseed": v["eseed"], "ct": v["ct"], "ss": v["ss"]} for v in vecs]
    return {
        "algorithm": "X-Wing",
        "source": "draft-connolly-cfrg-xwing-kem-11, Appendix C (copied verbatim)",
        "vectors": out,
    }


def main() -> None:
    d = Path(sys.argv[1])
    for name, doc in (("mlkem768", mlkem(d)), ("mldsa65", mldsa(d)), ("xwing", xwing(d))):
        (OUT / f"{name}.json").write_text(json.dumps(doc, indent=1) + "\n")
        print(name, "written")


if __name__ == "__main__":
    main()
