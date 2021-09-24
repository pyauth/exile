from enum import Enum

class YKOATHConstants:
    device_prefix = "yubico yubikey"
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

    class OATHType(Enum):
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

    class Algorithm(Enum):
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

    class Response(Enum):
        SUCCESS = b'\x90\x00'
        NO_SPACE = b'\x6a\x84'
        NOT_FOUND = b'\x69\x84'
        AUTH_REQUIRED = b'\x69\x82'
        WRONG_SYNTAX = b'\x6a\x80'
        GENERIC_ERROR = b'\x65\x81'
        MORE_DATA_AVAILABLE = b'\x61'
