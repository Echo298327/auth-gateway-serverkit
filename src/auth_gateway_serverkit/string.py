import re


def is_valid_user_name(string: str) -> bool:
    # Define a regex pattern for valid names including numbers
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", string):
        return False
    # Check the length of the username
    if not (3 <= len(string) <= 20):
        return False
    return True


def is_valid_name(string: str) -> bool:
    # Define a regex pattern for valid names
    if not re.fullmatch(r"[a-zA-Z]+", string):
        return False
    # Check the length of the name
    if not (3 <= len(string) <= 20):
        return False
    return True


def is_valid_email(string: str) -> bool:
    # Define a regex pattern for valid email addresses
    return bool(re.fullmatch(r"[^@]+@[^@]+\.[^@]+", string))
