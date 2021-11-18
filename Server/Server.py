import logging
import selectors
import socket
import handlers


class Server:

    def __init__(self, endpoint: tuple):
        self._endpoint = endpoint
        self.__sel = selectors.DefaultSelector()
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.bind(endpoint)
        self.__sock.listen(100)
        self.__sock.setblocking(False)
        self.__sel.register(self.__sock, selectors.EVENT_READ, self.accept)

    def accept(self, sock, mask):
        handlers.ConnectionHandler(self.__sel, sock).accept()

    def run(self):
        logging.info("Server start running.")
        while True:
            events = self.__sel.select(timeout=None)
            if events:
                logging.info("Server start handle the events: " + str(events))
            for key, mask in events:
                callback = key.data
                # logging.info("calling : " + str(callback))
                callback(key.fileobj, mask)
