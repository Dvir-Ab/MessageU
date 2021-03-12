import logging


class LogException(Exception):
    def __init__(self, *args, **kwargs):
        logging.error(*args, **kwargs)


class ConnectionException(LogException):
    pass


class InvalidCodeException(LogException):
    pass


class DataException(LogException):
    pass


class MissingDataException(DataException):
    pass


class DataNotMatchException(DataException):
    pass


class BrokenConnectionException(LogException):
    pass


class RegistrationException(LogException):
    pass


class VersionException(LogException):
    pass


def log_error(msg, exception: Exception):
    logging.debug(str(msg) + "\nthe following exception has been raised:\n", exception)


def log_info(msg: str):
    logging.info(msg)
