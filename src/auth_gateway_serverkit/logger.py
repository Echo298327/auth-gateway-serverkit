import logging
import json
import sys


class JsonFormatter(logging.Formatter):
    # ANSI escape codes for colors
    COLORS = {
        "ERROR": "\033[91m",  # Red
        "WARNING": "\033[93m",  # Yellow
        "RESET": "\033[0m"  # Reset to default
    }

    def __init__(self, datefmt="%Y-%m-%d %H:%M:%S"):
        """
        Initialize the formatter with a custom date format.
        :param datefmt: Date format for the log messages.
        """
        super().__init__(datefmt=datefmt)

    def format(self, record):
        log_message = {
            "time": self.formatTime(record, self.datefmt),
            "name": record.name,
            "level": record.levelname,
            "message": record.getMessage()
        }

        if record.levelno >= logging.ERROR:
            log_message.update({
                "line": record.lineno,
            })

        # Apply color based on log level
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        return f"{color}{json.dumps(log_message)}{self.COLORS['RESET']}"


def init_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(JsonFormatter())
        logger.addHandler(stream_handler)
    return logger
