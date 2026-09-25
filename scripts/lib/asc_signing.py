"""Create the distribution certificate and App Store profiles via the App Store
Connect API. Driven by scripts/setup-ios-signing.sh; not meant to be run alone.

Reads the key id + issuer from ~/.arca/asc-api-key and the private key from
~/.appstoreconnect/private_keys/. Prints nothing secret.
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

import jwt

HOME = os.path.expanduser("~")
SIGNING_DIR = os.environ.get("ARCA_SIGNING_DIR", os.path.join(HOME, ".arca", "signing"))
KEY_FILE = os.environ.get("ARCA_ASC_KEY", os.path.join(HOME, ".arca", "asc-api-key"))

BUNDLE_IDS = [
    "no.sybr.vault.ios",
    "no.sybr.vault.ios.autofill",
    "no.sybr.vault.ios.widgets",
]
PROFILE_DIR = os.path.join(HOME, "Library", "Developer", "Xcode", "UserData",
                           "Provisioning Profiles")


def _credentials():
    with open(KEY_FILE) as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    if len(lines) < 2:
        sys.exit(f"{KEY_FILE} needs the key id on line 1 and the issuer uuid on line 2.")
    key_id, issuer = lines[0], lines[1]
    p8 = os.path.join(HOME, ".appstoreconnect", "private_keys", f"AuthKey_{key_id}.p8")
    if not os.path.exists(p8):
        sys.exit(f"no private key at {p8}. The .p8 downloads exactly once.")
    with open(p8) as f:
        return key_id, issuer, f.read()


KEY_ID, ISSUER, PRIVATE_KEY = _credentials()


def call(method, path, body=None):
    """One API request. Returns (status, decoded-json)."""
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER, "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
        PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": KEY_ID, "typ": "JWT"},
    )
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"https://api.appstoreconnect.apple.com{path}", data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except ValueError:
            return e.code, {"raw": raw.decode(errors="replace")[:500]}


def fail(what, status, payload):
    lines = [f"{what} failed (HTTP {status})"]
    for err in payload.get("errors", []):
        lines.append(f"  {err.get('title')}: {err.get('detail')}")
    if not payload.get("errors"):
        lines.append(f"  {payload}")
    sys.exit("\n".join(lines))


def distribution_certificate(csr):
    """The account's distribution certificate, creating one if there is none.

    Reused when present: Apple caps how many a team may hold, and quietly
    minting a second on every run would burn that allowance in three releases.
    """
    status, payload = call("GET", "/v1/certificates?limit=200")
    if status != 200:
        fail("listing certificates", status, payload)
    for d in payload.get("data", []):
        if d["attributes"]["certificateType"] == "DISTRIBUTION":
            print(f"   reusing {d['attributes']['name']} "
                  f"(expires {d['attributes']['expirationDate'][:10]})")
            return d["id"], None

    status, payload = call("POST", "/v1/certificates", {
        "data": {
            "type": "certificates",
            "attributes": {"certificateType": "DISTRIBUTION", "csrContent": csr},
        }
    })
    if status not in (200, 201):
        fail("creating the distribution certificate", status, payload)
    attrs = payload["data"]["attributes"]
    print(f"   created {attrs['name']} (expires {attrs['expirationDate'][:10]})")
    return payload["data"]["id"], attrs["certificateContent"]


def certificate_content(cert_id):
    status, payload = call("GET", f"/v1/certificates/{cert_id}")
    if status != 200:
        fail("downloading the certificate", status, payload)
    return payload["data"]["attributes"]["certificateContent"]


def profile_name_on_disk(path):
    """The `Name` inside a .mobileprovision, or "" if it cannot be read.

    A .mobileprovision is a CMS envelope around a plain plist. The payload is
    lifted out by slicing between the plist markers rather than shelling out to
    `security cms`: this runs once per file in the directory, and an unreadable
    or foreign file must not abort the setup.
    """
    try:
        with open(path, "rb") as f:
            blob = f.read()
        start = blob.index(b"<?xml")
        end = blob.index(b"</plist>") + len(b"</plist>")
        import plistlib

        return plistlib.loads(blob[start:end]).get("Name", "")
    except Exception:
        return ""


def bundle_id_map():
    status, payload = call("GET", "/v1/bundleIds?limit=200&filter[platform]=IOS")
    if status != 200:
        fail("listing bundle ids", status, payload)
    found = {d["attributes"]["identifier"]: d["id"] for d in payload.get("data", [])}
    missing = [b for b in BUNDLE_IDS if b not in found]
    if missing:
        sys.exit("these App IDs are not registered in the developer portal:\n  "
                 + "\n  ".join(missing))
    return found


def main():
    with open(os.path.join(SIGNING_DIR, "dist.csr")) as f:
        csr = f.read()

    cert_id, content = distribution_certificate(csr)
    if content is None:
        content = certificate_content(cert_id)
    with open(os.path.join(SIGNING_DIR, "dist.cer"), "wb") as f:
        f.write(base64.b64decode(content))

    bundles = bundle_id_map()

    # Existing profiles under the names we are about to create, so a re-run
    # replaces rather than accumulating. A profile is pinned to the certificates
    # it was built with, so one made against a replaced certificate could not be
    # reused anyway.
    #
    # Matched by NAME, which is the constraint Apple actually enforces — it
    # rejects a duplicate name with a 409. Matching on the bundleId relationship
    # instead looks more precise and silently matches nothing: /v1/profiles omits
    # relationship `data` unless the caller asks for `include=bundleId`, so the
    # cleanup found nothing and the create then collided.
    status, payload = call("GET", "/v1/profiles?limit=200")
    if status != 200:
        fail("listing profiles", status, payload)
    wanted_names = {f"Arca App Store {b}" for b in BUNDLE_IDS}
    stale = [
        (d["id"], d["attributes"]["name"])
        for d in payload.get("data", [])
        if d["attributes"]["name"] in wanted_names
    ]

    os.makedirs(PROFILE_DIR, exist_ok=True)
    for profile_id, name in stale:
        call("DELETE", f"/v1/profiles/{profile_id}")
        print(f"   removed stale profile {name}")

    # And the copies already on disk. Xcode selects a profile by NAME, so
    # leaving last run's file next to this run's — same name, different uuid,
    # one of them revoked — means the build may pick the dead one and fail with
    # a message about the certificate rather than about the duplicate.
    for entry in os.listdir(PROFILE_DIR):
        if not entry.endswith(".mobileprovision"):
            continue
        path = os.path.join(PROFILE_DIR, entry)
        if profile_name_on_disk(path) in wanted_names:
            os.remove(path)

    for bundle in BUNDLE_IDS:
        name = f"Arca App Store {bundle}"
        status, payload = call("POST", "/v1/profiles", {
            "data": {
                "type": "profiles",
                "attributes": {"name": name, "profileType": "IOS_APP_STORE"},
                "relationships": {
                    "bundleId": {"data": {"type": "bundleIds", "id": bundles[bundle]}},
                    "certificates": {"data": [{"type": "certificates", "id": cert_id}]},
                },
            }
        })
        if status not in (200, 201):
            fail(f"creating the profile for {bundle}", status, payload)
        attrs = payload["data"]["attributes"]
        path = os.path.join(PROFILE_DIR, f"{payload['data']['id']}.mobileprovision")
        with open(path, "wb") as f:
            f.write(base64.b64decode(attrs["profileContent"]))
        print(f"   {name}")


if __name__ == "__main__":
    main()
