#!/usr/bin/env python3
import copy
import datetime
import hashlib
import importlib.util
import pathlib
import plistlib
import unittest

spec = importlib.util.spec_from_file_location('signing', pathlib.Path(__file__).with_name('prepare-autofill-signing.py'))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)

class ProfileTests(unittest.TestCase):
    def test_provisioning_stub_requests_desktop_capabilities(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        desktop = plistlib.loads((root / 'apps/desktop/src-tauri/Entitlements.plist').read_bytes())
        stub = plistlib.loads((root / 'apps/macos/ProvisionStub/ProvisionStub.entitlements').read_bytes())
        # The helper obtains the profile embedded in the desktop app. Every
        # restricted capability sealed into that app must be requested here.
        for capability in ('com.apple.developer.authentication-services.autofill-credential-provider',
                           'com.apple.security.application-groups'):
            with self.subTest(capability=capability):
                self.assertEqual(stub.get(capability), desktop[capability])

    def setUp(self):
        self.profile = {'ExpirationDate': datetime.datetime.now() + datetime.timedelta(days=1), 'Entitlements': {
            'com.apple.developer.team-identifier': 'TEAM',
            'com.apple.application-identifier': 'TEAM.test.autofill',
            'com.apple.developer.authentication-services.autofill-credential-provider': True,
            'com.apple.security.application-groups': ['group.no.sybr.vault'],
            'keychain-access-groups': ['TEAM.*']}}

    def test_matching_extension_profile(self):
        self.assertTrue(signing.eligible(self.profile, 'test.autofill', 'TEAM'))

    def test_rejects_host_wildcard_expired_or_missing_capability(self):
        for key, value in [('com.apple.application-identifier', 'TEAM.test'),
                           ('com.apple.application-identifier', 'TEAM.*'),
                           ('com.apple.developer.team-identifier', 'OTHER'),
                           ('com.apple.developer.authentication-services.autofill-credential-provider', False),
                           ('com.apple.security.application-groups', []),
                           ('keychain-access-groups', ['OTHER.*'])]:
            with self.subTest(key=key, value=value):
                profile = copy.deepcopy(self.profile)
                profile['Entitlements'][key] = value
                self.assertFalse(signing.eligible(profile, 'test.autofill', 'TEAM'))
        self.profile['ExpirationDate'] = datetime.datetime(2000, 1, 1)
        self.assertFalse(signing.eligible(self.profile, 'test.autofill', 'TEAM'))

class SelectionTests(unittest.TestCase):
    def profile(self, bundle, certificate=b'current', device='this-mac', days=1):
        return {'ExpirationDate': datetime.datetime.now() + datetime.timedelta(days=days),
                'DeveloperCertificates': [certificate], 'ProvisionedDevices': [device],
                'Entitlements': {'com.apple.developer.team-identifier': 'TEAM',
                                 'com.apple.application-identifier': 'TEAM.' + bundle,
                                 signing.CAPABILITY: True,
                                 'com.apple.security.application-groups': ['group.no.sybr.vault'],
                                 'keychain-access-groups': ['TEAM.*']}}

    def test_reject_expired_foreign_device_and_missing_private_key(self):
        current = hashlib.sha1(b'current').hexdigest()
        profiles = [('expired', self.profile('app', days=-1)),
                    ('other device', self.profile('app', device='other-mac')),
                    ('missing key', self.profile('app', certificate=b'unavailable'))]
        with self.assertRaises(ValueError):
            signing.select_profiles(profiles, [current], ['app'], 'TEAM', 'this-mac')

    def test_pick_one_available_identity_authorized_by_both_profiles(self):
        current = hashlib.sha1(b'current').hexdigest()
        other = hashlib.sha1(b'other').hexdigest()
        profiles = [('newer but wrong certificate', self.profile('app', b'other', days=10)),
                    ('app profile', self.profile('app')),
                    ('extension profile', self.profile('extension'))]
        plan = signing.select_profiles(profiles, [other, current], ['app', 'extension'], 'TEAM', 'this-mac')
        self.assertEqual(plan['identity'], current)
        self.assertEqual(plan['profiles'], {'app': 'app profile', 'extension': 'extension profile'})

    def test_missing_extension_profile_does_not_silently_downgrade(self):
        with self.assertRaises(ValueError):
            signing.select_profiles([('app', self.profile('app'))],
                                    [hashlib.sha1(b'current').hexdigest()],
                                    ['app', 'extension'], 'TEAM', 'this-mac')

    def test_provisioning_udid_takes_precedence_over_hardware_uuid(self):
        from unittest.mock import patch
        with patch.object(signing.subprocess, 'check_output', return_value=
                          b'{"SPHardwareDataType":[{"platform_UUID":"hardware", "provisioning_UDID":"device"}]}'):
            self.assertEqual(signing.local_device(), 'device')


if __name__ == '__main__':
    unittest.main()
