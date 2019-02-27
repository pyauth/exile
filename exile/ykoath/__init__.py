import struct
from collections import namedtuple
from ..scard import i2b, SCardManager
from .const import YKOATHConstants

YKOATHCredential = namedtuple("YKOATHCredential", ("name", "oath_type", "algorithm"))

class YKOATHError(Exception):
    pass

class YKOATH(YKOATHConstants):
    """
    See https://developers.yubico.com/OATH/YKOATH_Protocol.html
    """
    def __init__(self, scm: SCardManager = None):
        self.scm = SCardManager() if scm is None else scm
        self.send_apdu(cla=0, ins=self.Instruction.SELECT, p1=0x04, p2=0, data=self.Application.OATH)

    def send_apdu(self, **kwargs):
        with self.scm:
            res = self.scm.send_apdu(**kwargs)
        if res[-2:] != self.Response.SUCCESS.value:
            raise YKOATHError(self.Response(res[-2:]))
        return res

    def put(self, credential_name: str, secret: bytes, require_touch=False,
            oath_type=YKOATHConstants.OATHType.TOTP, algorithm=YKOATHConstants.Algorithm.SHA1, digits=6):
        secret_header = i2b(oath_type.value | algorithm.value) + i2b(digits)
        # secret = hmac_shorten_key(secret, algorithm)
        secret = secret.ljust(self.HMAC_MINIMUM_KEY_SIZE, b'\x00')
        data = i2b(self.Tag.NAME) + i2b(len(credential_name)) + credential_name.encode()
        data += i2b(self.Tag.KEY) + i2b(len(secret_header) + len(secret)) + secret_header + secret
        if require_touch:
            data += i2b(self.Tag.PROPERTY) + i2b(self.Properties.REQUIRE_TOUCH)
        return self.send_apdu(cla=0, ins=self.Instruction.PUT, p1=0, p2=0, data=data)

    def delete(self, credential_name: str):
        data = i2b(self.Tag.NAME) + i2b(len(credential_name)) + credential_name.encode()
        return self.send_apdu(cla=0, ins=self.Instruction.DELETE, p1=0, p2=0, data=data)

    def reset(self):
        return self.send_apdu(cla=0, ins=self.Instruction.RESET, p1=0xde, p2=0xad, data=b"")

    def list(self):
        return self.send_apdu(cla=0, ins=self.Instruction.LIST, p1=0, p2=0, data=b"")

    def calculate(self, credential_name: str, challenge: bytes, want_truncated_response=True):
        if not isinstance(challenge, bytes):
            challenge = int_to_bytestring(challenge)
        data = i2b(self.Tag.NAME) + i2b(len(credential_name)) + credential_name.encode()
        data += i2b(self.Tag.CHALLENGE) + i2b(len(challenge)) + challenge
        p2 = 0x01 if want_truncated_response else 0
        res = self.send_apdu(cla=0, ins=self.Instruction.CALCULATE, p1=0, p2=p2, data=data)
        assert res[0] == self.Tag.TRUNCATED_RESPONSE if want_truncated_response else self.Tag.RESPONSE
        res_len, digits = res[1], res[2]
        if want_truncated_response:
            return str(struct.unpack('>I', res[3:3 + res_len - 1])[0]).zfill(digits)
        else:
            return res[3:3 + res_len - 1]

    def __iter__(self):
        res = self.list()[:-2]
        while res:
            name_tag, name_len, alg = res[0], res[1], res[2]
            assert name_tag == self.Tag.NAME_LIST
            algorithm, oath_type = self.Algorithm(alg & 0x0f), self.OATHType(alg & 0xf0)
            name_data = res[3:3 + name_len - 1]
            yield YKOATHCredential(name=name_data.decode(), oath_type=oath_type, algorithm=algorithm)
            res = res[name_len + 2:]

def int_to_bytestring(i: int, padding=8):
    result = bytearray()
    while i != 0:
        result.append(i & 0xFF)
        i >>= 8
    return bytes(bytearray(reversed(result)).rjust(padding, b'\0'))
