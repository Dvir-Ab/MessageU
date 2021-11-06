import socket
import struct
import uuid
import dbClasses
import exceptions
import selectors


def connect(address):
    if not address:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        exceptions.log_info("trying to connect: " + str((address[0], 8080)))
        sock.connect((address[0], 8080))
    except Exception as e:
        raise exceptions.ConnectionException(e)
    return sock


class ConnectionHandler:
    """handle the connection with the clients"""
    def __init__(self, sel: selectors.DefaultSelector, sock: socket.socket):
        self.__requests_tbl = {'rgstr': 100, 'usr_lst': 101, 'usr_key': 102, 'send_msg': 103,
                               'pull_msg': 104}
        self.__response_tbl = {'rgstr_succeeded': 1000, 'usr_lst_returned': 1001,
                               'usr_key_returned': 1002, 'msgs_pulled': 1004, 'msg_received': 1003, 'gnrl_err': 9000}
        ids_name = ['sym_request']
        self.__msgs_ids= { name: val for name, val in zip(range(1,len(ids_name) + 1), ids_name)}
        self.__sock = sock
        self._target_address = None
        self.__VER__, self.__UID_LEN__, self.__PUB_KEY_SIZE__, self.__NAME_LEN__, self.__max_pack__ =\
            0x02, 16, 160, 255, 1024
        self.__selector = sel

    def accept(self):
        """accept a connection request from clients"""
        conn, self._target_address = self.__sock.accept()
        exceptions.log_info("accept connection: " + str(conn) + ", from: " + str(self._target_address))
        conn.setblocking(False)
        self.__read(conn)

    def __handle_header(self, data: bytes):
        fields = struct.unpack('<' + str(self.__UID_LEN__) + 's c I', data[:self.__UID_LEN__ + 5])
        other_uid, msg_type, content_size = fields
        return other_uid, int.from_bytes(msg_type, 'little'), content_size

    def __handle_msg_type(self, msg_type: int, content_size: int, sender, target):
        if msg_type == self.__msgs_ids['sym_request']:  # request symmetric key
            if content_size != 0:
                raise exceptions.DataException("no message content expected")
            self.__send(self.__response_tbl['msg_received'],
                        [target, dbClasses.MsgTbl().insert(sender, target, msg_type, b'')])
            return
        if msg_type in range(2, 5) and content_size == 0:
            raise exceptions.MissingDataException("expect for payload but the payload size is 0.")

    def __handle_content(self, data: bytes, content_size: int, conn: socket.socket):
        content = data
        left_to_read = content_size - len(data)
        if left_to_read > 0:
            rec_cnt = len(data)
            BLOCK_SIZE = 1 << 14
            while content_size > rec_cnt:
                bytes_to_read = min(BLOCK_SIZE, abs(content_size - rec_cnt))
                tmp = conn.recv(bytes_to_read)
                if not tmp:
                    break
                content += tmp
                rec_cnt += len(tmp)
            exceptions.log_info("received " + str(len(content)) + ' bytes, from ' + str(content_size) + ' bytes.')
        elif left_to_read < 0:
            content = content[:content_size]
        return struct.unpack('<' + str(len(content)) + 's', content)

    def __handle_message(self, conn: socket.socket, usr_id: bytes, data: bytes) -> None:
        """handle message from the server's client and save it until the target pull it
            conn :param - connection from client
            usr_id :param - source client uuid
            data :param - the message data
            Exception :raises - if connection broken or message is too big or data isn't correlate with the protocol
            None :returns"""
        exceptions.log_info("start to handle message.")
        other_uid, msg_type, content_size = self.__handle_header(data)
        data = data[self.__UID_LEN__ + 5:]   # ToDo: move to using index instead of copy substring into data
        exceptions.log_info("the message info is: " + str((msg_type, content_size)))
        self.__handle_msg_type(msg_type, content_size, usr_id, other_uid)
        content = self.__handle_content(data, content_size, conn)
        msg_id = dbClasses.MsgTbl().insert(usr_id, other_uid, msg_type, content[0])
        if msg_id == 0:
            self.__send(self.__response_tbl['gnrl_err'])
            return
        self.__send(self.__response_tbl['msg_received'], [other_uid, msg_id])

    def __read(self, conn: socket.socket) -> None:
        """read the data from the socket and handle the request, if valid.
            conn :param - connection from client
            Exception :raises - if connection broken or message is too big or
                                the data received isn't correlate with the protocol
            None :returns"""
        header_len = 22
        try:
            data = conn.recv(self.__max_pack__)  # Should be ready
            if len(data) < header_len:  # header_len should be <= len(data)
                print('closing', conn)
                self.__selector.unregister(conn)
                conn.close()
                return None
            fields = struct.unpack('<' + str(self.__UID_LEN__) + 's B B I', data[:header_len])
            exceptions.log_info("received: " + str(fields) + "...")
            usr_id, ver, code, payload_size = fields
            data = data[header_len:]
            if ver != 2:  # change this condition to allow old version to get treatment
                raise exceptions.VersionException("Error: the client, version is: ", ver, ".")
            if code not in self.__requests_tbl.values():
                raise exceptions.InvalidCodeException("Error: the code, ", code, ", doesn't match any request.")
            if code == self.__requests_tbl['rgstr']:
                self.register(data, payload_size)
                return None
            elif code == self.__requests_tbl['usr_lst'] or code == self.__requests_tbl['pull_msg']:
                if payload_size:
                    raise exceptions.DataException("no payload expected!")
                if code == self.__requests_tbl['pull_msg']:
                    self.__send(self.__response_tbl['msgs_pulled'], dbClasses.MsgTbl().pull(usr_id))
                    return None
                self.__send(self.__response_tbl['usr_lst_returned'], dbClasses.ClientTbl().get_usrs(usr_id))
                return
            elif code == self.__requests_tbl['usr_key']:
                # other_uid = struct.unpack('>' + str(UID_LEN) + 's', data[:UID_LEN])
                self.__send(self.__response_tbl['usr_key_returned'],
                            dbClasses.ClientTbl().get_usr(data[:self.__UID_LEN__]))  # [::-1]))
                return None
            # send msg
            self.__handle_message(conn, usr_id, data)
        except exceptions.ConnectionException as conExcept:  # as conExcept:
            exceptions.log_error("while reading from " + str(self._target_address), conExcept)
            return
        except Exception as e:
            exceptions.log_error("", e)
            self.__send(self.__response_tbl['gnrl_err'])
        finally:
            if conn:
                conn.close()

    def __send(self, code, payload=None):
        """send the response to the client
            code :param - response code
            payload :param - response payload
            Exception :raises  if failed to connect or message is too big or
                               the response data isn't correlate with the protocol
            the length of the response :returns"""
        exceptions.log_info("sending the response: " + str(code))
        if not self._target_address:
            raise Exception("error: client address lost, can't send messages.")
        if code not in self.__response_tbl.values():
            raise exceptions.InvalidCodeException("Error: the code, ", code, ", is not valid.")
        to_send = struct.pack('<B H', self.__VER__, code)  # pack the version and the respond code
        if code == self.__response_tbl['gnrl_err']:
            to_send += struct.pack('<I', 0)
        elif code == self.__response_tbl['msgs_pulled'] or code == self.__response_tbl['usr_lst_returned']:
            tmp = b''
            if code == self.__response_tbl['usr_lst_returned']:
                for rec in payload:
                    name_len = len(rec[1])
                    tmp += struct.pack('<' + str(self.__UID_LEN__) + 's' + str(name_len) +
                                       's ' + str(self.__NAME_LEN__-name_len) + 'x', rec[0], rec[1])
            else:
                for rec in payload:
                    tmp += struct.pack('<' + str(self.__UID_LEN__) + 's I c I ' + str(len(rec[3])) + 's',
                                       rec[0], rec[1], int(rec[2]).to_bytes(1, 'little'), len(rec[3]), rec[3])
            to_send += struct.pack('<I', len(tmp)) + tmp
        elif code != self.__response_tbl['gnrl_err'] and not payload:
            raise exceptions.MissingDataException("Error: expect to receive some data to send, but received None.")
        elif code == self.__response_tbl['msg_received']:
            tmp = struct.pack('<' + str(self.__UID_LEN__) + 's I', payload[0], payload[1])
            to_send += struct.pack('<I', len(tmp)) + tmp
        elif code == self.__response_tbl['usr_key_returned']:
            to_send += struct.pack('<I ' + str(self.__UID_LEN__) + 's ' + str(self.__PUB_KEY_SIZE__) + 's',
                                   self.__PUB_KEY_SIZE__ + self.__UID_LEN__, *payload)
        elif code == self.__response_tbl['rgstr_succeeded']:
            to_send += struct.pack('< I ' + str(self.__UID_LEN__) + 's', self.__UID_LEN__, payload.bytes)  # [::-1])
        padding_size = self.__max_pack__ - len(to_send)
        if padding_size > 0:
            to_send += struct.pack(str(padding_size) + 'x')
        sock = connect(self._target_address)
        exceptions.log_info("sending " + str(len(to_send)) + " bytes.")
        if sock.sendall(to_send) == 0:
            raise exceptions.BrokenConnectionException("socket connection broken.")
        sock.close()
        return len(to_send)

    def register(self, data: str, payloadSize: int):
        name, pub_key = 256, 160
        if payloadSize not in range(pub_key+1, pub_key + name):
            raise exceptions.RegistrationException("the payload size is out of range, " + str(payloadSize))
        fields = struct.unpack('<' + str(payloadSize - pub_key) + 's ' + str(pub_key) + 's', data[:payloadSize])
        # fields = [x[::-1] for x in fields]
        name, pub_key = fields
        usr_id = uuid.uuid4()
        client = dbClasses.ClientTbl()
        if not client.insert(usr_id.bytes, name.lower(), pub_key):
            raise exceptions.RegistrationException("the user with id: ", usr_id, "already exist")
        self.__send(self.__response_tbl['rgstr_succeeded'], usr_id)
        exceptions.log_info("The client " + name + " just register.")
        return
