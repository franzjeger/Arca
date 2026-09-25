#!/usr/bin/env python3
"""Select local development profiles and prepare/verify both signed bundles."""
import argparse
import datetime
import fnmatch
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile

DESKTOP_ID = 'no.sybr.vault'
EXTENSION_ID = 'no.sybr.vault.autofill-host.autofill'
CAPABILITY = 'com.apple.developer.authentication-services.autofill-credential-provider'


def eligible(profile, bundle_id, team, certificate=None, device=None):
    ent = profile.get('Entitlements', {})
    return (
        profile.get('ExpirationDate', datetime.datetime.min) > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        and ent.get('com.apple.developer.team-identifier') == team
        and ent.get('com.apple.application-identifier') == f'{team}.{bundle_id}'
        and ent.get(CAPABILITY) is True
        and 'group.no.sybr.vault' in ent.get('com.apple.security.application-groups', [])
        and any(fnmatch.fnmatchcase(f'{team}.no.sybr.vault.shared', group)
                for group in ent.get('keychain-access-groups', []))
        and (certificate is None or certificate.upper() in {
            hashlib.sha1(cert).hexdigest().upper() for cert in profile.get('DeveloperCertificates', [])})
        and (device is None or device in profile.get('ProvisionedDevices', []))
    )


def decode_profile(path):
    return plistlib.loads(subprocess.check_output(
        ['security', 'cms', '-D', '-i', str(path)], stderr=subprocess.DEVNULL))


def local_device():
    hardware = json.loads(subprocess.check_output(['system_profiler', 'SPHardwareDataType', '-json']))
    record = hardware['SPHardwareDataType'][0]
    # Apple Silicon's provisioning UDID is not its IOPlatformUUID.
    return record.get('provisioning_UDID') or record['platform_UUID']


def select_profiles(profiles, identities, bundle_ids, team, device):
    for identity in identities:
        selected = {}
        for bundle_id in bundle_ids:
            matches = [(profile['ExpirationDate'], str(path)) for path, profile in profiles
                       if eligible(profile, bundle_id, team, identity, device)]
            if not matches:
                break
            selected[bundle_id] = max(matches)[1]
        if len(selected) == len(bundle_ids):
            return {'identity': identity, 'team': team, 'device': device, 'profiles': selected}
    raise ValueError('No matching local Apple Development identity and profiles for ' + ', '.join(bundle_ids)
                     + '. In Xcode, sign in to Apple Accounts and provision ArcaSign and ArcaHost '
                     '(including ArcaAutoFill) for this Mac. Restore missing private keys before retrying.')


def make_plan(team, desktop_only=False):
    output = subprocess.check_output(['security', 'find-identity', '-v', '-p', 'codesigning'], text=True)
    identities = re.findall(r'\b([A-Fa-f0-9]{40})\s+"Apple Development[^\"]*"', output)
    candidates = [Path('/Applications/Arca.app/Contents/embedded.provisionprofile'),
                  Path('/Applications/Arca.app/Contents/PlugIns/ArcaAutoFill.appex/Contents/embedded.provisionprofile')]
    for root in [Path.home() / 'Library/Developer/Xcode/UserData/Provisioning Profiles',
                 Path.home() / 'Library/MobileDevice/Provisioning Profiles']:
        candidates.extend(root.glob('*.provisionprofile'))
    profiles = []
    for path in candidates:
        if path.is_file():
            try:
                profiles.append((path, decode_profile(path)))
            except (subprocess.CalledProcessError, plistlib.InvalidFileException, ValueError):
                continue
    ids = [DESKTOP_ID] if desktop_only else [DESKTOP_ID, EXTENSION_ID]
    return select_profiles(profiles, identities, ids, team, local_device())


def prepare(bundle, template, output, plan):
    contents = Path(bundle) / 'Contents'
    info_path = contents / 'Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    bundle_id = info['CFBundleIdentifier']
    team = plan['team']
    source = Path(plan['profiles'][bundle_id])
    if not eligible(decode_profile(source), bundle_id, team, plan['identity'], plan['device']):
        raise ValueError('Selected profile no longer authorizes this bundle, certificate and Mac')
    destination = contents / 'embedded.provisionprofile'
    if source != destination:
        shutil.copyfile(source, destination)
    ent = plistlib.loads(Path(template).read_text().replace('$(AppIdentifierPrefix)', team + '.').encode())
    ent['com.apple.application-identifier'] = team + '.' + bundle_id
    ent['com.apple.developer.team-identifier'] = team
    Path(output).write_bytes(plistlib.dumps(ent))
    if Path(bundle).suffix == '.appex':
        info['ArcaKeychainAccessGroup'] = team + '.no.sybr.vault.shared'
        info_path.write_bytes(plistlib.dumps(info))
    print(f'Prepared {bundle_id} with {source.name}')


def verify(bundle):
    contents = Path(bundle) / 'Contents'
    info = plistlib.loads((contents / 'Info.plist').read_bytes())
    profile = decode_profile(contents / 'embedded.provisionprofile')
    sealed = plistlib.loads(subprocess.check_output(
        ['codesign', '-d', '--entitlements', '-', '--xml', str(bundle)], stderr=subprocess.DEVNULL))
    team = sealed['com.apple.developer.team-identifier']
    with tempfile.TemporaryDirectory() as temporary:
        prefix = temporary + '/certificate'
        subprocess.run(['codesign', '-d', '--extract-certificates=' + prefix, str(bundle)],
                       check=True, capture_output=True)
        certificate = hashlib.sha1(Path(prefix + '0').read_bytes()).hexdigest()
    if not eligible(profile, info['CFBundleIdentifier'], team, certificate, local_device()):
        raise ValueError('Profile does not authorize this bundle, signing certificate and Mac')
    if sealed.get('com.apple.application-identifier') != team + '.' + info['CFBundleIdentifier']:
        raise ValueError('Signed application identifier mismatch')
    group = team + '.no.sybr.vault.shared'
    if (sealed.get(CAPABILITY) is not True
            or 'group.no.sybr.vault' not in sealed.get('com.apple.security.application-groups', [])
            or group not in sealed.get('keychain-access-groups', [])):
        raise ValueError('Signed AutoFill, App Group or keychain capability is missing')
    if Path(bundle).suffix == '.appex':
        if info.get('ArcaKeychainAccessGroup') != group or sealed.get('com.apple.security.app-sandbox') is not True:
            raise ValueError('AutoFill keychain group or sandbox entitlement is missing')
    subprocess.run(['codesign', '--verify', '--deep', '--strict', str(bundle)], check=True)
    print(f'Profile, certificate, device and sealed capabilities verified: {info["CFBundleIdentifier"]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--plan', metavar='OUTPUT')
    actions.add_argument('--prepare', nargs=4, metavar=('BUNDLE', 'TEMPLATE', 'ENTITLEMENTS', 'PLAN'))
    actions.add_argument('--verify', metavar='BUNDLE')
    parser.add_argument('--team', default='LY6LJ395B8')
    parser.add_argument('--desktop-only', action='store_true')
    args = parser.parse_args()
    try:
        if args.plan:
            Path(args.plan).write_text(json.dumps(make_plan(args.team, args.desktop_only), indent=2) + '\n')
        elif args.prepare:
            bundle, template, output, plan = args.prepare
            prepare(bundle, template, output, json.loads(Path(plan).read_text()))
        else:
            verify(args.verify)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Signing failed: {error}\n')


if __name__ == '__main__':
    main()
