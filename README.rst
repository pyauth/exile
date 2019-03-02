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
    from exile import YKOATH, botocore_signers

    def write_active_aws_key_to_yubikey():
        credentials = boto3.Session().get_credentials()

        key_name = "exile-{}-SigV4".format(credentials.access_key)
        secret = b"AWS4" + credentials.secret_key.encode()
        print("Writing YubiKey OATH SigV4 credential", key_name, "for", credentials.access_key)
        YKOATH().put(key_name, secret, algorithm=YKOATH.Algorithm.SHA256)

        key_name = "exile-{}-HmacV1".format(credentials.access_key)
        secret = credentials.secret_key.encode()
        print("Writing YubiKey OATH HmacV1 credential", key_name, "for", credentials.access_key)
        YKOATH().put(key_name, secret, algorithm=YKOATH.Algorithm.SHA1)

    write_active_aws_key_to_yubikey()
    botocore_signers.install()

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
