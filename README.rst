Exile: Python Web Authentication Relying Party library
======================================================

**Exile** stores your AWS access key on your YubiKey device and uses it to sign your AWS API requests, protecting you
against credential theft.

Installation
------------
::

    pip install exile

Synopsis
--------

.. code-block:: python

    import base64, logging
    import boto3, botocore.auth
    from exile import YKOATH, SCardManager

    logging.basicConfig(level=logging.INFO)

    ykoath = YKOATH(SCardManager())

    def write_active_aws_key_to_yubikey():
        credentials = boto3.Session().get_credentials()
        secret_name = "exile-" + credentials.access_key[len("AKIA"):]
        # This is for SigV4 only. Other formats will require a separate secret
        secret = b"AWS4" + credentials.secret_key.encode()
        print("Writing YubiKey OATH credential", secret_name, "for", credentials.access_key)
        ykoath.put(secret_name, secret, algorithm=YKOATH.Algorithm.SHA256)

    write_active_aws_key_to_yubikey()

    class YKSigV4Auth(botocore.auth.SigV4Auth):
        def signature(self, string_to_sign, request):
            key_name = "exile-" + self.credentials.access_key[len("AKIA"):]
            k_date = ykoath.calculate(key_name, request.context['timestamp'][0:8].encode(), want_truncated_response=False)
            k_region = self._sign(k_date, self._region_name)
            k_service = self._sign(k_region, self._service_name)
            k_signing = self._sign(k_service, "aws4_request")
            return self._sign(k_signing, string_to_sign, hex=True)

    botocore.auth.SigV4Auth.signature = YKSigV4Auth.signature

    print("Using YubiKey credential to perform AWS call")
    print(boto3.client("sts").get_caller_identity())

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
