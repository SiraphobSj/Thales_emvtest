import logging

def init(filename, loglevel):

    formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    logger = logging.getLogger()

    file_handler = logging.FileHandler(filename)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    level = logging.DEBUG
    if loglevel == "debug":
        level = logging.DEBUG
    elif loglevel == "info":
        level = logging.INFO
    elif loglevel == "warning":
        level = logging.WARNING
    elif loglevel == "error":
        level = logging.ERROR
    elif loglevel == "critical":
        level = logging.CIRITICAL

    logger.setLevel(level)

def debug(msg):
    logging.debug(msg)

def info(msg):
    logging.info(msg)

def warning(msg):
    logging.warning(msg)

def error(msg):
    logging.error(msg)

def critical(msg):
    logging.critical(msg)
