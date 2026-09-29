"""The Developer ID certificate and profiles a published macOS release signs
with, via the App Store Connect API. Driven by scripts/setup-macos-signing.sh.

    asc_developer_id.py --check    read only: what exists, what is missing
    asc_developer_id.py            create what is missing, install the profiles

A certificate the account already has is reused when this Mac can sign with
it: its private key is in a keychain here (restored from a backup of the Mac
that made it, say), or it is our own key file's, as when the Account Holder made
the certificate in the portal from our signing request. Apple caps how many
Developer ID certificates a team may hold, so a new one is asked for only when
none can be used, and only an Account Holder may make one; with an API key that
ends in instructions for the portal. Prints nothing secret.
"""

import base64
import hashlib
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from asc_signing import call, certificate_content, fail, profile_name_on_disk  # noqa: E402

HOME = os.path.expanduser("~")
SIGNING_DIR = os.environ.get("ARCA_SIGNING_DIR", os.path.join(HOME, ".arca", "signing"))
KEY = os.path.join(SIGNING_DIR, "developer-id.key")
CSR = os.path.join(SIGNING_DIR, "developer-id.csr")
CER = os.path.join(SIGNING_DIR, "developer-id.cer")

# The desktop app and its AutoFill extension, as prepare-autofill-signing.py
# names them.
BUNDLE_IDS = ["no.sybr.vault", "no.sybr.vault.autofill-host.autofill"]
PROFILE_DIR = os.path.join(HOME, "Library", "Developer", "Xcode", "UserData",
                           "Provisioning Profiles")
CERTIFICATE_TYPES = ("DEVELOPER_ID_APPLICATION", "DEVELOPER_ID_APPLICATION_G2")


def profile_name(bundle):
    return f"Arca Developer ID {bundle}"


def developer_id_certificates():
    status, payload = call("GET", "/v1/certificates?limit=200")
    if status != 200:
        fail("listing certificates", status, payload)
    return [d for d in payload.get("data", [])
            if d["attributes"]["certificateType"] in CERTIFICATE_TYPES]


def signable():
    """SHA-1s of the code-signing identities in this Mac's keychains: the
    certificates it has private keys for."""
    output = subprocess.run(["security", "find-identity", "-v", "-p", "codesigning"],
                            capture_output=True, text=True, check=True).stdout
    return {h.upper() for h in re.findall(r"\b([A-Fa-f0-9]{40})\b", output)}


def local_public_key():
    """The public half of the key setup-macos-signing.sh made, or None."""
    if not os.path.exists(KEY):
        return None
    return subprocess.run(["openssl", "pkey", "-in", KEY, "-pubout"],
                          capture_output=True, check=True).stdout


def public_key(der):
    return subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-pubkey"],
                          input=der, capture_output=True, check=True).stdout


def ours(der, identities, mine):
    """Whether this Mac holds the private key for an account certificate: in a
    keychain, or as our key file, which is how a certificate the Account Holder
    made in the portal from our signing request is recognised."""
    return (hashlib.sha1(der).hexdigest().upper() in identities
            or (mine is not None and public_key(der) == mine))


def contents(certificate):
    return base64.b64decode(certificate_content(certificate["id"]))


def bundle_ids():
    status, payload = call("GET", "/v1/bundleIds?limit=200&filter[platform]=MAC_OS")
    if status != 200:
        fail("listing bundle ids", status, payload)
    found = {d["attributes"]["identifier"]: d["id"] for d in payload.get("data", [])}
    missing = [b for b in BUNDLE_IDS if b not in found]
    if missing:
        sys.exit("these macOS App IDs are not registered in the developer portal:\n  "
                 + "\n  ".join(missing))
    return found


def existing_profiles():
    status, payload = call("GET", "/v1/profiles?limit=200&filter[profileType]=MAC_APP_DIRECT")
    if status != 200:
        fail("listing profiles", status, payload)
    wanted = {profile_name(b) for b in BUNDLE_IDS}
    return [(d["id"], d["attributes"]["name"], d["attributes"]["expirationDate"][:10])
            for d in payload.get("data", []) if d["attributes"]["name"] in wanted]


def check():
    certificates = developer_id_certificates()
    identities = signable()
    mine = local_public_key()
    for c in certificates:
        here = ("private key here" if ours(contents(c), identities, mine)
                else "private key NOT on this Mac")
        print(f"   certificate: {c['attributes']['name']} "
              f"(expires {c['attributes']['expirationDate'][:10]}, {here})")
    if not certificates:
        print("   certificate: none yet")
    bundle_ids()
    for identifier in BUNDLE_IDS:
        print(f"   App ID: {identifier}")
    profiles = existing_profiles()
    for _, name, expires in profiles:
        print(f"   profile: {name} (expires {expires})")
    if not profiles:
        print("   profiles: none yet")


def certificate():
    """One this Mac can sign with if the account has it; otherwise a new one
    from our CSR."""
    identities = signable()
    mine = local_public_key()
    for c in developer_id_certificates():
        der = contents(c)
        if ours(der, identities, mine):
            print(f"   reusing {c['attributes']['name']} "
                  f"(expires {c['attributes']['expirationDate'][:10]})")
            with open(CER, "wb") as f:
                f.write(der)
            return c["id"]
    with open(CSR) as f:
        csr = f.read()
    status, payload = call("POST", "/v1/certificates", {
        "data": {
            "type": "certificates",
            "attributes": {"certificateType": "DEVELOPER_ID_APPLICATION", "csrContent": csr},
        }
    })
    if status == 403:
        # Apple lets no API key make one: only the Account Holder, by hand.
        sys.exit(f"""Only the Account Holder can create a Developer ID certificate, and not
through an API key. Make it from this Mac's signing request:
  1. https://developer.apple.com/account/resources/certificates/add
     Developer ID Application ▸ Continue
  2. G2 Sub-CA, not the preselected Previous Sub-CA: that one's
     certificates all expire on 2027-02-01
  3. Upload {CSR} ▸ Continue
Then run scripts/setup-macos-signing.sh again. Nothing to download: it finds
the certificate by its key.""")
    if status not in (200, 201):
        fail("creating the Developer ID certificate", status, payload)
    attrs = payload["data"]["attributes"]
    with open(CER, "wb") as f:
        f.write(base64.b64decode(attrs["certificateContent"]))
    print(f"   created {attrs['name']} (expires {attrs['expirationDate'][:10]})")
    return payload["data"]["id"]


def main():
    if "--check" in sys.argv:
        check()
        return
    cert_id = certificate()
    bundles = bundle_ids()

    # Replaced, never accumulated: a profile is pinned to the certificate it was
    # made with, and Xcode picks by name, so a stale one next to a fresh one is
    # a coin toss between a working signature and a revoked one.
    for profile_id, name, _ in existing_profiles():
        call("DELETE", f"/v1/profiles/{profile_id}")
        print(f"   removed stale profile {name}")
    os.makedirs(PROFILE_DIR, exist_ok=True)
    wanted = {profile_name(b) for b in BUNDLE_IDS}
    for entry in os.listdir(PROFILE_DIR):
        path = os.path.join(PROFILE_DIR, entry)
        if entry.endswith(".provisionprofile") and profile_name_on_disk(path) in wanted:
            os.remove(path)

    for bundle in BUNDLE_IDS:
        status, payload = call("POST", "/v1/profiles", {
            "data": {
                "type": "profiles",
                "attributes": {"name": profile_name(bundle), "profileType": "MAC_APP_DIRECT"},
                "relationships": {
                    "bundleId": {"data": {"type": "bundleIds", "id": bundles[bundle]}},
                    "certificates": {"data": [{"type": "certificates", "id": cert_id}]},
                },
            }
        })
        if status not in (200, 201):
            fail(f"creating the profile for {bundle}", status, payload)
        attrs = payload["data"]["attributes"]
        path = os.path.join(PROFILE_DIR, f"{payload['data']['id']}.provisionprofile")
        with open(path, "wb") as f:
            f.write(base64.b64decode(attrs["profileContent"]))
        print(f"   {profile_name(bundle)}")


if __name__ == "__main__":
    main()
