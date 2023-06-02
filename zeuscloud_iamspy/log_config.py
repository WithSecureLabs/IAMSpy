import logging


def build_logger(debug_level=logging.DEBUG):
    # create logger
    logger = logging.getLogger("iamspy")
    logger.setLevel(debug_level)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(debug_level)
    # create formatter and add it to the handlers
    formatter = logging.Formatter("%(asctime)s|%(name)s|%(levelname)s|%(message)s")
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(ch)
