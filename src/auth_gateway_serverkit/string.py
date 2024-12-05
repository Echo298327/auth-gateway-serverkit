import re


def is_valid_user_name(string: str) -> bool:
    # Define a regex pattern for valid names including numbers
    return bool(re.fullmatch(r"[a-zA-Z0-9_-]+", string))


def is_valid_email(string: str) -> bool:
    # Define a regex pattern for valid email addresses
    return bool(re.fullmatch(r"[^@]+@[^@]+\.[^@]+", string))