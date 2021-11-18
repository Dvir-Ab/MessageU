import logging
import Server


def init_log():
    logging.basicConfig(filename='server.log', format='%(asctime)s [%(levelname)s]:%(message)s',
                        level=logging.INFO)


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
    server = Server.Server(('127.0.0.1', int(srv_port)))
    server.run()


if __name__ == '__main__':
    main()
