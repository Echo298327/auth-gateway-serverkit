""" Logging configuration for the auth_gateway package."""
import logging
import sys


class SimpleFormatter(logging.Formatter):
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
        timestamp = self.formatTime(record, self.datefmt)
        level = record.levelname
        name = record.name
        message = record.getMessage()

        # Apply color based on log level
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        formatted_message = f"[{timestamp}] {level} | {name} | {message}"
        return f"{color}{formatted_message}{self.COLORS['RESET']}"


def init_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(SimpleFormatter())
        logger.addHandler(stream_handler)
    return logger
