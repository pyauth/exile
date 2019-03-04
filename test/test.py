#!/usr/bin/env python

import os, sys, unittest, json, collections, base64, datetime
import boto3, botocore.auth

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))  # noqa

from exile import YKOATH, TOTP, SCardManager, botocore_signers

class TestExile(unittest.TestCase):
    def test_scard_manager(self):
        for reader in SCardManager():
            with reader:
                pass

    def test_exile_totp(self):
        TOTP().save("google", "JBSWY3DPEHPK3PXP")
        TOTP().get("google")
        TOTP().verify("260153", label="google", at=datetime.datetime.fromtimestamp(1297553958))
        otpauth_uri = 'otpauth://totp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Secure%20App'
        TOTP().save_otpauth_uri(otpauth_uri)
        TOTP().verify("260153", label="Secure%20App:alice%40google.com", at=datetime.datetime.fromtimestamp(1297553958))

    def write_active_aws_key_to_yubikey(self):
        credentials = boto3.Session().get_credentials()

        key_name = "exile-{}-SigV4".format(credentials.access_key)
        secret = b"AWS4" + credentials.secret_key.encode()
        YKOATH().put(key_name, secret, algorithm=YKOATH.Algorithm.SHA256)

        key_name = "exile-{}-HmacV1".format(credentials.access_key)
        secret = credentials.secret_key.encode()
        YKOATH().put(key_name, secret, algorithm=YKOATH.Algorithm.SHA1)

    def test_exile(self):
        self.write_active_aws_key_to_yubikey()
        botocore_signers.install()

        boto3.client("sts").get_caller_identity()
        boto3.client("s3").generate_presigned_url(ClientMethod="get_object", Params={"Bucket": "foo", "Key": "bar"})

if __name__ == '__main__':
    unittest.main()
