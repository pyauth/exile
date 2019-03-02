import botocore.auth
from botocore.compat import encodebytes
from . import YKOATH

class YKSigV4Auth(botocore.auth.SigV4Auth):
    def signature(self, string_to_sign, request):
        if not hasattr(self, "_ykoath"):
            self._ykoath = YKOATH()
        key_name = "exile-{}-SigV4".format(self.credentials.access_key)
        k_date = self._ykoath.calculate(key_name,
                                        request.context["timestamp"][0:8].encode(),
                                        want_truncated_response=False)
        k_region = self._sign(k_date, self._region_name)
        k_service = self._sign(k_region, self._service_name)
        k_signing = self._sign(k_service, "aws4_request")
        return self._sign(k_signing, string_to_sign, hex=True)

class YKHmacV1Auth(botocore.auth.HmacV1Auth):
    def sign_string(self, string_to_sign):
        if not hasattr(self, "_ykoath"):
            self._ykoath = YKOATH()
        key_name = "exile-{}-HmacV1".format(self.credentials.access_key)
        digest = self._ykoath.calculate(key_name, string_to_sign.encode(), want_truncated_response=False)
        return encodebytes(digest).strip().decode("utf-8")

def install():
    botocore.auth.SigV4Auth.signature = YKSigV4Auth.signature
    botocore.auth.HmacV1Auth.sign_string = YKHmacV1Auth.sign_string
