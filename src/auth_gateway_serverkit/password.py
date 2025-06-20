""" password generation module."""
import string
import secrets


def generate_password():
    """
    Generate a random password that meets the following criteria:
    - At least one lowercase letter
    - At least one uppercase letter
    - At least one digit
    - At least one special character from the set !?#$%&
    - Total length of 10 characters
    :return: A randomly generated password that meets the criteria.
    """
    allowed_symbols = "!?#$%&"
    alphabet = string.ascii_letters + string.digits + allowed_symbols
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(10))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in allowed_symbols for c in password)):
            break
    return password
