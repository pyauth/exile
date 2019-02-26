import struct
from ..scard import i2b
from .const import YKOATHConstants

class YKOATHError(Exception):
    pass

class YKOATH(YKOATHConstants):
    """
    See https://developers.yubico.com/OATH/YKOATH_Protocol.html
    """
    def __init__(self, scm):
        self.scm = scm
        self.send_apdu(cla=0, ins=self.Instruction.SELECT, p1=0x04, p2=0, data=self.Application.OATH)

    def send_apdu(self, **kwargs):
        with self.scm:
            res = self.scm.send_apdu(**kwargs)
        if res[-2:] != self.Error.SUCCESS.value:
            raise YKOATHError(self.Error(res[-2:]))
        return res

    def put(self, credential_name, secret, require_touch=False,
            oath_type=YKOATHConstants.OATHType.TOTP, algorithm=YKOATHConstants.Algorithm.SHA1, digits=6):
        secret_header = i2b(oath_type | algorithm) + i2b(digits)
        # secret = hmac_shorten_key(secret, algorithm)
        secret = secret.ljust(self.HMAC_MINIMUM_KEY_SIZE, b'\x00')
        data = i2b(self.Tag.NAME) + i2b(len(credential_name)) + credential_name.encode()
        data += i2b(self.Tag.KEY) + i2b(len(secret_header) + len(secret)) + secret_header + secret
        if require_touch:
            data += i2b(self.Tag.PROPERTY) + i2b(self.Properties.REQUIRE_TOUCH)
        return self.send_apdu(cla=0, ins=self.Instruction.PUT, p1=0, p2=0, data=data)

    def delete(self, credential_name):
        data = i2b(self.Tag.NAME) + i2b(len(credential_name)) + credential_name.encode()
        return self.send_apdu(cla=0, ins=self.Instruction.DELETE, p1=0, p2=0, data=data)

    def reset(self):
        return self.send_apdu(cla=0, ins=self.Instruction.RESET, p1=0xde, p2=0xad, data=b"")

    def list(self):
        return self.send_apdu(cla=0, ins=self.Instruction.LIST, p1=0, p2=0, data=b"")

    def calculate(self, credential_name, challenge, want_truncated_response=True):
        if not isinstance(challenge, bytes):
            challenge = self.int_to_bytestring(challenge)
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

    def int_to_bytestring(self, i, padding=8):
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        return bytes(bytearray(reversed(result)).rjust(padding, b'\0'))
