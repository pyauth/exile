import struct
from enum import Enum
from ..scard import i2b


class YKOATHConstants:
    HMAC_MINIMUM_KEY_SIZE = 14

    class Tag:
        NAME = 0x71
        NAME_LIST = 0x72
        KEY = 0x73
        CHALLENGE = 0x74
        RESPONSE = 0x75
        TRUNCATED_RESPONSE = 0x76
        NO_RESPONSE = 0x77
        PROPERTY = 0x78
        VERSION = 0x79
        IMF = 0x7a
        ALGORITHM = 0x7b
        TOUCH = 0x7c

    class OATHType:
        HOTP = 0x10
        TOTP = 0x20

    class Properties:
        REQUIRE_TOUCH = 0x02

    class Instruction:
        SELECT = 0xa4
        PUT = 0x01
        DELETE = 0x02
        SET_CODE = 0x03
        RESET = 0x04
        LIST = 0xa1
        CALCULATE = 0xa2
        VALIDATE = 0xa3
        CALCULATE_ALL = 0xa4
        SEND_REMAINING = 0xa5

    class Algorithm:
        SHA1 = 0x01
        SHA256 = 0x02
        SHA512 = 0x03

    class Application:
        OTP = b'\xa0\x00\x00\x05\x27\x20\x01'
        MGR = b'\xa0\x00\x00\x05\x27\x47\x11\x17'
        OPGP = b'\xd2\x76\x00\x01\x24\x01'
        OATH = b'\xa0\x00\x00\x05\x27\x21\x01'
        PIV = b'\xa0\x00\x00\x03\x08'
        U2F = b'\xa0\x00\x00\x06\x47\x2f\x00\x01'

    class Error(Enum):
        SUCCESS = b'\x90\x00'
        NO_SPACE = b'\x6a\x84'
        NOT_FOUND = b'\x69\x84'
        AUTH_REQUIRED = b'x69\x82'
        WRONG_SYNTAX = b'\x6a\x80'
        GENERIC_ERROR = b'\x65\x81'
        MORE_DATA_AVAILABLE = b'\x61'

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

    def put(self, credential_name, secret,
            oath_type=YKOATHConstants.OATHType.TOTP, algorithm=YKOATHConstants.Algorithm.SHA1, digits=6):
        secret_header = i2b(oath_type | algorithm) + i2b(digits)
        # secret = hmac_shorten_key(secret, algorithm)
        secret = secret.ljust(self.HMAC_MINIMUM_KEY_SIZE, b'\x00')
        data = i2b(self.Tag.NAME) + i2b(len(credential_name)) + credential_name.encode()
        data += i2b(self.Tag.KEY) + i2b(len(secret_header) + len(secret)) + secret_header + secret
        # data += bytearray([YKOATH.Tag.PROPERTY, YKOATH.Properties.REQUIRE_TOUCH])
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
            return str(struct.unpack('>I', res[3:3+res_len-1])[0]).zfill(digits)
        else:
            return res[3:3+res_len-1]

    def int_to_bytestring(self, i, padding=8):
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        return bytes(bytearray(reversed(result)).rjust(padding, b'\0'))
