from enum import Enum


class SCardConstants:
    """
    https://docs.microsoft.com/en-us/windows/desktop/api/winscard
    """
    MAX_BUFFER_SIZE = 264
    """Maximum Tx/Rx Buffer for short APDU"""
    MAX_BUFFER_SIZE_EXTENDED = 4 + 3 + (1 << 16) + 3
    """enhanced (64K + APDU + Lc + Le) Tx/Rx Buffer"""
    MAX_ATR_SIZE = 33
    MAX_READERNAME = 52
    class SCardStatus(Enum):
        S_SUCCESS = 0x00000000
        """No error was encountered."""
        F_INTERNAL_ERROR = 0x80100001
        """An internal consistency check failed."""
        E_CANCELLED = 0x80100002
        """The action was cancelled by an SCardCancel request."""
        E_INVALID_HANDLE = 0x80100003
        """The supplied handle was invalid."""
        E_INVALID_PARAMETER = 0x80100004
        """One or more of the supplied parameters could not be properly interpreted."""
        E_INVALID_TARGET = 0x80100005
        """Registry startup information is missing or invalid."""
        E_NO_MEMORY = 0x80100006
        """Not enough memory available to complete this command."""
        F_WAITED_TOO_LONG = 0x80100007
        """An internal consistency timer has expired."""
        E_INSUFFICIENT_BUFFER = 0x80100008
        """The data buffer to receive returned data is too small for the returned data."""
        E_UNKNOWN_READER = 0x80100009
        """The specified reader name is not recognized."""
        E_TIMEOUT = 0x8010000A
        """The user-specified timeout value has expired."""
        E_SHARING_VIOLATION = 0x8010000B
        """The smart card cannot be accessed because of other connections outstanding."""
        E_NO_SMARTCARD = 0x8010000C
        """The operation requires a Smart Card, but no Smart Card is currently in the device."""
        E_UNKNOWN_CARD = 0x8010000D
        """The specified smart card name is not recognized."""
        E_CANT_DISPOSE = 0x8010000E
        """The system could not dispose of the media in the requested manner."""
        E_PROTO_MISMATCH = 0x8010000F
        """The requested protocols are incompatible with the protocol currently in use with the smart card."""
        E_NOT_READY = 0x80100010
        """The reader or smart card is not ready to accept commands."""
        E_INVALID_VALUE = 0x80100011
        """One or more of the supplied parameters values could not be properly interpreted."""
        E_SYSTEM_CANCELLED = 0x80100012
        """The action was cancelled by the system, presumably to log off or shut down."""
        F_COMM_ERROR = 0x80100013
        """An internal communications error has been detected."""
        F_UNKNOWN_ERROR = 0x80100014
        """An internal error has been detected, but the source is unknown."""
        E_INVALID_ATR = 0x80100015
        """An ATR obtained from the registry is not a valid ATR string."""
        E_NOT_TRANSACTED = 0x80100016
        """An attempt was made to end a non-existent transaction."""
        E_READER_UNAVAILABLE = 0x80100017
        """The specified reader is not currently available for use."""
        P_SHUTDOWN = 0x80100018
        """The operation has been aborted to allow the server application to exit."""
        E_PCI_TOO_SMALL = 0x80100019
        """The PCI Receive buffer was too small."""
        E_READER_UNSUPPORTED = 0x8010001A
        """The reader driver does not meet minimal requirements for support."""
        E_DUPLICATE_READER = 0x8010001B
        """The reader driver did not produce a unique reader name."""
        E_CARD_UNSUPPORTED = 0x8010001C
        """The smart card does not meet minimal requirements for support."""
        E_NO_SERVICE = 0x8010001D
        """The Smart card resource manager is not running."""
        E_SERVICE_STOPPED = 0x8010001E
        """The Smart card resource manager has shut down."""
        E_UNEXPECTED = 0x8010001F
        """An unexpected card error has occurred."""
        E_ICC_INSTALLATION = 0x80100020
        """No primary provider can be found for the smart card."""
        E_ICC_CREATEORDER = 0x80100021
        """The requested order of object creation is not supported."""
        E_UNSUPPORTED_FEATURE = 0x80100022
        """This smart card does not support the requested feature."""
        E_DIR_NOT_FOUND = 0x80100023
        """The identified directory does not exist in the smart card."""
        E_FILE_NOT_FOUND = 0x80100024
        """The identified file does not exist in the smart card."""
        E_NO_DIR = 0x80100025
        """The supplied path does not represent a smart card directory."""
        E_NO_FILE = 0x80100026
        """The supplied path does not represent a smart card file."""
        E_NO_ACCESS = 0x80100027
        """Access is denied to this file."""
        E_WRITE_TOO_MANY = 0x80100028
        """The smart card does not have enough memory to store the information."""
        E_BAD_SEEK = 0x80100029
        """There was an error trying to set the smart card file object pointer."""
        E_INVALID_CHV = 0x8010002A
        """The supplied PIN is incorrect."""
        E_UNKNOWN_RES_MNG = 0x8010002B
        """An unrecognized error code was returned from a layered component."""
        E_NO_SUCH_CERTIFICATE = 0x8010002C
        """The requested certificate does not exist."""
        E_CERTIFICATE_UNAVAILABLE = 0x8010002D
        """The requested certificate could not be obtained."""
        E_NO_READERS_AVAILABLE = 0x8010002E
        """Cannot find a smart card reader."""
        E_COMM_DATA_LOST = 0x8010002F
        """A communications error with the smart card has been detected. Retry the operation."""
        E_NO_KEY_CONTAINER = 0x80100030
        """The requested key container does not exist on the smart card."""
        E_SERVER_TOO_BUSY = 0x80100031
        """The Smart Card Resource Manager is too busy to complete this operation."""

        W_UNSUPPORTED_CARD = 0x80100065
        """The reader cannot communicate with the card, due to ATR string configuration conflicts."""
        W_UNRESPONSIVE_CARD = 0x80100066
        """The smart card is not responding to a reset."""
        W_UNPOWERED_CARD = 0x80100067
        """Power has been removed from the smart card, so that further communication is not possible."""
        W_RESET_CARD = 0x80100068
        """The smart card has been reset, so any shared state information is invalid."""
        W_REMOVED_CARD = 0x80100069
        """The smart card has been removed, so further communication is not possible."""

        W_SECURITY_VIOLATION = 0x8010006A
        """Access was denied because of a security violation."""
        W_WRONG_CHV = 0x8010006B
        """The card cannot be accessed because the wrong PIN was presented."""
        W_CHV_BLOCKED = 0x8010006C
        """The card cannot be accessed because the maximum number of PIN entry attempts has been reached."""
        W_EOF = 0x8010006D
        """The end of the smart card file has been reached."""
        W_CANCELLED_BY_USER = 0x8010006E
        """The user pressed "Cancel" on a Smart Card Selection Dialog."""
        W_CARD_NOT_AUTHENTICATED = 0x8010006F
        """No PIN was presented to the smart card."""

    class Scope:
        USER = 0x0000
        """Scope in user space"""
        TERMINAL = 0x0001
        """Scope in terminal"""
        SYSTEM = 0x0002
        """Scope in system"""

    class Protocol:
        UNDEFINED = 0x0000
        """protocol not set"""
        UNSET = UNDEFINED
        T0 = 0x0001
        """T=0 active protocol."""
        T1 = 0x0002
        """T=1 active protocol."""
        RAW = 0x0004
        """Raw active protocol."""
        T15 = 0x0008
        """T=15 protocol."""
        ANY = T0 | T1
        """IFD determines prot."""

    class ShareMode:
        EXCLUSIVE = 0x0001
        """Exclusive mode only"""
        SHARED = 0x0002
        """Shared mode only"""
        DIRECT = 0x0003
        """Raw mode only"""

    class Disposition:
        LEAVE_CARD = 0x0000
        """Do nothing on close"""
        RESET_CARD = 0x0001
        """Reset on close"""
        UNPOWER_CARD = 0x0002
        """Power down on close"""
        EJECT_CARD = 0x0003
        """Eject on close"""

    class CardState:
        UNKNOWN = 0x0001
        """Unknown state"""
        ABSENT = 0x0002
        """Card is absent"""
        PRESENT = 0x0004
        """Card is present"""
        SWALLOWED = 0x0008
        """Card not powered"""
        POWERED = 0x0010
        """Card is powered"""
        NEGOTIABLE = 0x0020
        """Ready for PTS"""
        SPECIFIC = 0x0040
        """PTS has been set"""

    class ReaderState:
        UNAWARE = 0x0000
        """App wants status"""
        IGNORE = 0x0001
        """Ignore this reader"""
        CHANGED = 0x0002
        """State has changed"""
        UNKNOWN = 0x0004
        """Reader unknown"""
        UNAVAILABLE = 0x0008
        """Status unavailable"""
        EMPTY = 0x0010
        """Card removed"""
        PRESENT = 0x0020
        """Card inserted"""
        ATRMATCH = 0x0040
        """ATR matches card"""
        EXCLUSIVE = 0x0080
        """Exclusive Mode"""
        INUSE = 0x0100
        """Shared Mode"""
        MUTE = 0x0200
        """Unresponsive card"""
        UNPOWERED = 0x0400
        """Unpowered card"""
