Exile: Python Web Authentication Relying Party library
======================================================

**Exile** stores your AWS access key on your YubiKey device and uses it to sign your AWS API requests, protecting you
against credential theft.

Installation
------------
::

    pip install exile

On Linux, install ``libpcsclite-dev`` (``apt install libpcsclite-dev``, ``yum install pcsc-lite-devel``).

Synopsis
--------

.. code-block:: python

    import boto3, botocore.auth
    from exile import YKOATH

    ykoath = YKOATH()

    def write_active_aws_key_to_yubikey():
        credentials = boto3.Session().get_credentials()

        key_name = "exile-{}-SigV4".format(credentials.access_key)
        secret = b"AWS4" + credentials.secret_key.encode()
        print("Writing YubiKey OATH SigV4 credential", key_name, "for", credentials.access_key)
        ykoath.put(key_name, secret, algorithm=YKOATH.Algorithm.SHA256)

        key_name = "exile-{}-HmacV1".format(credentials.access_key)
        secret = credentials.secret_key.encode()
        print("Writing YubiKey OATH HmacV1 credential", key_name, "for", credentials.access_key)
        ykoath.put(key_name, secret, algorithm=YKOATH.Algorithm.SHA1)

    write_active_aws_key_to_yubikey()

    class YKSigV4Auth(botocore.auth.SigV4Auth):
        def signature(self, string_to_sign, request):
            key_name = "exile-{}-SigV4".format(self.credentials.access_key)
            k_date = ykoath.calculate(key_name, request.context["timestamp"][0:8].encode(), want_truncated_response=False)
            k_region = self._sign(k_date, self._region_name)
            k_service = self._sign(k_region, self._service_name)
            k_signing = self._sign(k_service, "aws4_request")
            return self._sign(k_signing, string_to_sign, hex=True)

    class YKHmacV1Auth(botocore.auth.HmacV1Auth):
        def sign_string(self, string_to_sign):
            key_name = "exile-{}-HmacV1".format(self.credentials.access_key)
            digest = ykoath.calculate(key_name, string_to_sign.encode(), want_truncated_response=False)
            return encodebytes(digest).strip().decode("utf-8")

    botocore.auth.SigV4Auth.signature = YKSigV4Auth.signature
    botocore.auth.HmacV1Auth.sign_string = YKHmacV1Auth.sign_string

    print("Using YubiKey credential to perform AWS call")
    print(boto3.client("sts").get_caller_identity())

    print("Using YubiKey credential to presign an S3 URL")
    print(boto3.client("s3").generate_presigned_url(ClientMethod="get_object", Params={"Bucket": "foo", "Key": "bar"}))

Authors
-------
* Andrey Kislyuk

Links
-----
* `Project home page (GitHub) <https://github.com/pyauth/exile>`_
* `Documentation (Read the Docs) <https://exile.readthedocs.io/en/latest/>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/exile>`_
* `Change log <https://github.com/pyauth/exile/blob/master/Changes.rst>`_

Bugs
----
Please report bugs, issues, feature requests, etc. on `GitHub <https://github.com/pyauth/exile/issues>`_.

License
-------
Licensed under the terms of the `Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_.

.. image:: https://img.shields.io/travis/com/pyauth/exile.svg
        :target: https://travis-ci.com/pyauth/exile
.. image:: https://codecov.io/github/pyauth/exile/coverage.svg?branch=master
        :target: https://codecov.io/github/pyauth/exile?branch=master
.. image:: https://img.shields.io/pypi/v/exile.svg
        :target: https://pypi.python.org/pypi/exile
.. image:: https://img.shields.io/pypi/l/exile.svg
        :target: https://pypi.python.org/pypi/exile
.. image:: https://readthedocs.org/projects/exile/badge/?version=latest
        :target: https://exile.readthedocs.io/
