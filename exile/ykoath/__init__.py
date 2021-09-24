import base64, struct, typing, hashlib, hmac
from collections import namedtuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from ..exceptions import YKOATHError
from ..scard import i2b, SCardManager, SCardReader
from .const import YKOATHConstants

YKOATHCredential = namedtuple("YKOATHCredential", ("name", "oath_type", "algorithm"))

class YKOATH(YKOATHConstants):
    """
    See https://developers.yubico.com/OATH/YKOATH_Protocol.html
    """
    def __init__(self, device: SCardReader = None, password: str = None) -> None:
        if device is None:
            for reader in SCardManager():
                if reader.name.lower().startswith(self.device_prefix):
                    device = reader
                    break
            else:
                raise YKOATHError("No YubiKey found")
        self.device = device
        res = self.send_apdu(cla=0, ins=self.Instruction.SELECT, p1=0x04, p2=0, data=self.Application.OATH)
        _, self._version, res = self.parse_tlv(res, self.Tag.VERSION)
        _, self._id, res = self.parse_tlv(res, self.Tag.NAME)
        _, self._challenge, res = self.parse_tlv(res)
        if self._challenge and password is not None:
            self.validate(password)

    def send_apdu(self, **kwargs):
        with self.device:
            res = self.device.send_apdu(**kwargs)
            while res[-2:-1] == self.Response.MORE_DATA_AVAILABLE.value:
                res = res[:-2] + self.device.send_apdu(cla=0, ins=self.Instruction.SEND_REMAINING, p1=0, p2=0, data=b"")
        if res[-2:] != self.Response.SUCCESS.value:
            raise YKOATHError(self.Response(res[-2:]))
        return res

    def parse_tlv(self, data, expect_tag=None):
        assert isinstance(data, bytes)
        tag, length = data[0], data[1]
        if expect_tag:
            assert tag == expect_tag
        value, data = data[2:2 + length], data[2 + length:]
        return tag, value, data

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

    def calculate(self, credential_name: str, challenge: typing.Union[bytes, int], want_truncated_response=True):
        chal_bytes = challenge if isinstance(challenge, bytes) else int_to_bytestring(challenge)
        data = i2b(self.Tag.NAME) + i2b(len(credential_name)) + credential_name.encode()
        data += i2b(self.Tag.CHALLENGE) + i2b(len(chal_bytes)) + chal_bytes
        p2 = 0x01 if want_truncated_response else 0
        res = self.send_apdu(cla=0, ins=self.Instruction.CALCULATE, p1=0, p2=p2, data=data)
        assert res[0] == self.Tag.TRUNCATED_RESPONSE if want_truncated_response else self.Tag.RESPONSE
        res_len, digits = res[1], res[2]
        if want_truncated_response:
            return str(struct.unpack('>I', res[3:3 + res_len - 1])[0]).zfill(digits)
        else:
            return res[3:3 + res_len - 1]

    def set_code(self, password):
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), self._id, 1000)
        test_challenge = b'01234567'
        test_response = hmac.new(key, test_challenge, 'sha256').digest()
        data = i2b(self.Tag.KEY) + i2b(len(key) + 1) + i2b(self.Algorithm.SHA256.value) + key
        data += i2b(self.Tag.CHALLENGE) + i2b(len(test_challenge)) + test_challenge
        data += i2b(self.Tag.RESPONSE) + i2b(len(test_response)) + test_response
        return self.send_apdu(cla=0, ins=self.Instruction.SET_CODE, p1=0, p2=0, data=data)

    def validate(self, password):
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), self._id, 1000)
        response = hmac.new(key, self._challenge, 'sha256').digest()
        data = i2b(self.Tag.RESPONSE) + i2b(len(response)) + response
        data += i2b(self.Tag.CHALLENGE) + i2b(len(self._challenge)) + self._challenge
        return self.send_apdu(cla=0, ins=self.Instruction.VALIDATE, p1=0, p2=0, data=data)

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

class TOTP(YKOATH):
    default_time_step = 30

    def save(self, label: str, secret: str):
        self.put(label, base64.b32decode(secret, casefold=True))

    def save_otpauth_uri(self, otpauth_uri: str):
        otpauth = urlparse(otpauth_uri)
        assert otpauth.scheme == "otpauth"
        assert otpauth.netloc == "totp"
        label = otpauth.path.lstrip("/")
        secret = parse_qs(otpauth.query)["secret"][0]
        self.save(secret=secret, label=label)

    def get(self, label: str, at: datetime = None, time_step: int = default_time_step):
        if at is None:
            at = datetime.now()
        return self.calculate(label, int(at.timestamp() / time_step))

    def verify(self, code: str, label: str, at: datetime = None, time_step: int = default_time_step):
        if self.get(label=label, at=at, time_step=time_step) != code:
            raise YKOATHError("TOTP code mismatch")
