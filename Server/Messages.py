import struct


class RequestIF:
    def fill(self, *args):
        """
        fill the request message from *args
        :param args: argument to fill the protocol message with
        :return: filled request
        """
        pass

    def unpack_request(self, data: str) -> list:
        """
        unpack the request
        :param data: the request as string
        :return: the unpacked request as a list
        """
        pass


class RequestHeader(RequestIF):
    def __init__(self, client_id=0, version=0, code: int = 0, payload: int = 0):
        self._client_id, self._version, self._code, self._payload = \
            client_id, version, code, payload

    def unpack_request(self, data: str) -> tuple:
        header_len = 22
        if len(data) < header_len:
            return tuple()
        return struct.unpack('<' + str(self.__UID_LEN__) + 's B B I', data[:header_len])


class RegistryRequest(RequestIF):
    def __init__(self, name: str = '', pub_key: str = ''):
        self._name, self._pub_key = name, pub_key

    def unpack_request(self, data: str) -> list:
        # ToDo: return the unpacked request
        pass

