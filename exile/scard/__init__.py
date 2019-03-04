import platform, logging
from enum import Enum
from binascii import b2a_hex, a2b_hex
from ctypes import (cdll, c_void_p, POINTER, c_ulong, c_char, c_uint32, byref, create_string_buffer, c_wchar,
                    cast, c_char_p)
from ..exceptions import SCardError
from .const import SCardConstants

logger = logging.getLogger(__name__)

def i2b(i):
    return i.to_bytes(1, byteorder="little")

def b2i(data):
    return int(b2a_hex(data), 16)

class SCARDCONTEXT(c_uint32):
    pass

class SCARDHANDLE(c_uint32):
    pass

class SCard(SCardConstants):
    """
    See https://docs.microsoft.com/en-us/windows/desktop/api/winscard/
    """
    def __init__(self):
        if platform.system() == "Darwin":
            lib_name = "PCSC.framework/PCSC"
        elif platform.system() == "Linux":
            lib_name = "libpcsclite.so"
        elif platform.system() == "Windows":
            lib_name = "winscard.dll"
        self.pcsc = cdll.LoadLibrary(lib_name)

    def __call__(self, method, *args):
        logger.debug(method + str(args))
        status = getattr(self.pcsc, method)(*args)
        if status != self.SCardStatus.S_SUCCESS.value:
            raise SCardError(self.SCardStatus(status))
        return status

    def EstablishContext(self, dwScope: SCardConstants.Scope,
                         pvReserved1: c_void_p,
                         pvReserved2: c_void_p,
                         phContext: SCARDCONTEXT) -> SCardConstants.SCardStatus:
        """
        The SCardEstablishContext function establishes the resource manager context (the scope) within which database
        operations are performed.
        """
        return self("SCardEstablishContext", dwScope, pvReserved1, pvReserved2, phContext)

    def ReleaseContext(self, hContext: SCARDCONTEXT) -> SCardConstants.SCardStatus:
        """
        The SCardReleaseContext function closes an established resource manager context, freeing any resources allocated
        under that context, including SCARDHANDLE objects and memory allocated using the SCARD_AUTOALLOCATE length
        designator.
        """
        return self("SCardReleaseContext", hContext)

    def IsValidContext(self, hContext: SCARDCONTEXT) -> SCardConstants.SCardStatus:
        """
        The SCardIsValidContext function determines whether a smart card context handle is valid.
        """
        return self("SCardIsValidContext", hContext)

    def SetTimeout(self, hContext: SCARDCONTEXT, dwTimeout: int) -> SCardConstants.SCardStatus:
        return self("SCardSetTimeout", hContext, dwTimeout)

    def Connect(self, hContext: SCARDCONTEXT,
                szReader: c_char_p,
                dwShareMode: SCardConstants.ShareMode,
                dwPreferredProtocols: SCardConstants.Protocol,
                phCard: SCARDHANDLE,
                pdwActiveProtocol: SCardConstants.Protocol) -> SCardConstants.SCardStatus:
        """
        The SCardConnect function establishes a connection (using a specific resource manager context) between the
        calling application and a smart card contained by a specific reader. If no card exists in the specified reader,
        an error is returned.
        """
        return self("SCardConnect", hContext, szReader, dwShareMode, dwPreferredProtocols, phCard, pdwActiveProtocol)

    def Reconnect(self, hCard: SCARDHANDLE,
                  dwShareMode: SCardConstants.ShareMode,
                  dwPreferredProtocols: SCardConstants.Protocol,
                  dwInitialization: SCardConstants.Disposition,
                  pdwActiveProtocol: SCardConstants.Protocol) -> SCardConstants.SCardStatus:
        """
        The SCardReconnect function reestablishes an existing connection between the calling application and a smart
        card. This function moves a card handle from direct access to general access, or acknowledges and clears an
        error condition that is preventing further access to the card.
        """
        return self("SCardConnect", hCard, dwShareMode, dwPreferredProtocols, dwInitialization, pdwActiveProtocol)

    def Disconnect(self, hCard: SCARDHANDLE, dwDisposition: SCardConstants.Disposition) -> SCardConstants.SCardStatus:
        """
        The SCardDisconnect function terminates a connection previously opened between the calling application and a
        smart card in the target reader.
        """
        return self("SCardDisconnect", hCard, dwDisposition)

    def BeginTransaction(self, hCard: SCARDHANDLE) -> SCardConstants.SCardStatus:
        """
        The SCardBeginTransaction function starts a transaction.

        The function waits for the completion of all other transactions before it begins. After the transaction starts,
        all other applications are blocked from accessing the smart card while the transaction is in progress.
        """
        return self("SCardBeginTransaction", hCard)

    def EndTransaction(self, hCard: SCARDHANDLE,
                       dwDisposition: SCardConstants.Disposition) -> SCardConstants.SCardStatus:
        """
        The SCardEndTransaction function completes a previously declared transaction, allowing other applications to
        resume interactions with the card.
        """
        return self("SCardEndTransaction", hCard, dwDisposition)

    def CancelTransaction(self, hCard: SCARDHANDLE) -> SCardConstants.SCardStatus:
        raise NotImplementedError()

    def Status(self, hCard: SCARDHANDLE,
               mszReaderNames: str,
               pcchReaderLen,
               pdwState: SCardConstants.CardState,
               pdwProtocol: SCardConstants.Protocol,
               pbAtr,
               pcbAtrLen) -> SCardConstants.SCardStatus:
        """
        The SCardStatus function provides the current status of a smart card in a reader. You can call it any time
        after a successful call to SCardConnect and before a successful call to SCardDisconnect. It does not affect the
        state of the reader or reader driver.
        """
        return self("SCardStatus", hCard, mszReaderNames, pcchReaderLen, pdwState, pdwProtocol, pbAtr, pcbAtrLen)

    def GetStatusChange(self, hContext: SCARDCONTEXT,
                        dwTimeout,
                        rgReaderStates: SCardConstants.ReaderState,
                        cReaders) -> SCardConstants.SCardStatus:
        return self("SCardGetStatusChange", hContext, dwTimeout, rgReaderStates, cReaders)

    def Control(self, hCard: SCARDHANDLE,
                dwControlCode,
                pbSendBuffer,
                cbSendLength,
                pbRecvBuffer,
                cbRecvLength,
                lpBytesReturned) -> SCardConstants.SCardStatus:
        """
        The SCardControl function gives you direct control of the reader. You can call it any time after a successful
        call to SCardConnect and before a successful call to SCardDisconnect. The effect on the state of the reader
        depends on the control code.
        """
        return self("SCardControl", hCard, dwControlCode, pbSendBuffer, cbSendLength, pbRecvBuffer, cbRecvLength,
                    lpBytesReturned)

    def Transmit(self, hCard: SCARDHANDLE,
                 pioSendPci,
                 pbSendBuffer,
                 cbSendLength,
                 pioRecvPci,
                 pbRecvBuffer,
                 pcbRecvLength) -> SCardConstants.SCardStatus:
        """
        The SCardTransmit function sends a service request to the smart card and expects to receive data back from the
        card.
        """
        return self("SCardTransmit", hCard, pioSendPci, pbSendBuffer, cbSendLength, pioRecvPci, pbRecvBuffer,
                    pcbRecvLength)

    def ListReaderGroups(self, hContext: SCARDCONTEXT, mszGroups, pcchGroups) -> SCardConstants.SCardStatus:
        return self("SCardListReaderGroups", hContext, mszGroups, pcchGroups)

    def ListReaders(self, hContext: SCARDCONTEXT, mszGroups, mszReaders, pcchReaders) -> SCardConstants.SCardStatus:
        """
        The SCardListReaders function provides the list of readers within a set of named reader groups, eliminating
        duplicates.

        The caller supplies a list of reader groups, and receives the list of readers within the named groups.
        Unrecognized group names are ignored. This function only returns readers within the named groups that
        are currently attached to the system and available for use.
        """
        return self("SCardListReaders", hContext, mszGroups, mszReaders, pcchReaders)

    def Cancel(self, hContext: SCARDCONTEXT) -> SCardConstants.SCardStatus:
        """
        The SCardCancel function terminates all outstanding actions within a specific resource manager context.

        The only requests that you can cancel are those that require waiting for external action by the smart card or
        user. Any such outstanding action requests will terminate with a status indication that the action was
        canceled. This is especially useful to force outstanding SCardGetStatusChange calls to terminate.
        """
        return self("SCardCancel", hContext)

    def GetAttrib(self, hCard: SCARDHANDLE, dwAttrId, pbAttr, pcbAttrLen) -> SCardConstants.SCardStatus:
        """
        The SCardGetAttrib function retrieves the current reader attributes for the given handle. It does not affect the
        state of the reader, driver, or card.
        """
        return self("SCardGetAttrib", hCard, dwAttrId, pbAttr, pcbAttrLen)

    def SetAttrib(self, hCard: SCARDHANDLE, dwAttrId, pbAttr, cbAttrLen) -> SCardConstants.SCardStatus:
        """
        The SCardSetAttrib function sets the given reader attribute for the given handle. It does not affect the state
        of the reader, reader driver, or smart card. Not all attributes are supported by all readers (nor can they be
        set at all times) as many of the attributes are under direct control of the transport protocol.
        """
        return self("SCardSetAttrib", hCard, dwAttrId, pbAttr, cbAttrLen)


class SCardManager(SCard):
    def __init__(self):
        SCard.__init__(self)
        self.ctx = SCARDCONTEXT()
        self.protocol = c_ulong()
        self.EstablishContext(dwScope=self.Scope.SYSTEM, pvReserved1=0, pvReserved2=0, phContext=byref(self.ctx))

    def _split_multi_string(self, ms):
        p = cast(ms, POINTER(c_char))
        return p[:len(ms)].split(b"\0")

    def _get_send_pci(self):
        if self.protocol.value == self.Protocol.T0:
            return self.pcsc.g_rgSCardT0Pci
        elif self.protocol.value == self.Protocol.T1:
            return self.pcsc.g_rgSCardT1Pci

    def __iter__(self):
        pcch_readers = c_uint32()
        self.ListReaders(hContext=self.ctx, mszGroups=0, mszReaders=0, pcchReaders=byref(pcch_readers))
        s = create_string_buffer(b"\0" * pcch_readers.value)
        self.ListReaders(hContext=self.ctx, mszGroups=0, mszReaders=s, pcchReaders=byref(pcch_readers))
        for reader in self._split_multi_string(s):
            if reader:
                yield SCardReader(name=reader.decode(), manager=self)


class SCardReader(SCard):
    def __init__(self, name: str, manager: SCardManager) -> None:
        SCard.__init__(self)
        self.name = name
        self.manager = manager
        self.handle = SCARDHANDLE()

    def __enter__(self):
        self.Connect(hContext=self.manager.ctx,
                     szReader=c_char_p(self.name.encode()),
                     dwShareMode=self.ShareMode.SHARED,
                     dwPreferredProtocols=self.Protocol.ANY,
                     phCard=byref(self.handle),
                     pdwActiveProtocol=byref(self.manager.protocol))

    def __exit__(self, exc_type, exc_value, traceback):
        self.Disconnect(hCard=self.handle, dwDisposition=self.Disposition.LEAVE_CARD)

    def send_apdu(self, cla, ins, p1, p2, data):
        send_buf = create_string_buffer(i2b(cla) + i2b(ins) + i2b(p1) + i2b(p2) + i2b(len(data)) + data)
        recv_buf = create_string_buffer(b"\0" * self.MAX_BUFFER_SIZE_EXTENDED)
        recv_len = c_ulong(len(recv_buf))
        self.Transmit(hCard=self.handle,
                      pioSendPci=self.manager._get_send_pci(),
                      pbSendBuffer=send_buf,
                      cbSendLength=len(send_buf),
                      pioRecvPci=0,
                      pbRecvBuffer=recv_buf,
                      pcbRecvLength=byref(recv_len))
        return recv_buf.raw[:recv_len.value]
