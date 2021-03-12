import selectors
import ssl
import socket
import handlers
import logging


def init_log():
    logging.basicConfig(filename='server.log', format='%(asctime)s [%(levelname)s]:%(message)s',
                        level=logging.INFO)


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
                logging.info("calling : " + str(callback))
                callback(key.fileobj, mask)


def main():
    init_log()
    with open('server.info', 'r') as srv_fd:
        srv_data = srv_fd.read()
        if srv_data and len(srv_data.split('\n')) == 1:
            srv_port = srv_data
        else:
            logging.fatal("bad data in the file sever.info, failed to extract the server port.")
            print("Error: bad data in the file: 'sever.info'.")
            return
    server = Server(('127.0.0.1', int(srv_port)))
    server.run()


if __name__ == '__main__':
    main()
