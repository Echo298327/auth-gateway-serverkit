""" firebase user API Module for the auth gateway serverkit."""

from firebase_admin import auth as firebase_auth
from auth_gateway_serverkit.logger import init_logger
from typing import Optional, Dict, Any


logger = init_logger("serverkit.firebase.user")

def create_user(email: str, password: Optional[str] = None, display_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a user in Firebase Auth.

    Args:
        email: User's email address
        password: User's password (optional, Firebase will generate if not provided)
        display_name: User's display name (optional)

    Returns:
        dict: Firebase user data including UID

    Raises:
        Exception: If Firebase user creation fails
    """
    try:
        # Prepare user creation arguments
        user_args = {
            'email': email,
            'disabled': False
        }

        if password:
            user_args['password'] = password

        if display_name:
            user_args['display_name'] = display_name

        # Create user in Firebase
        firebase_user = firebase_auth.create_user(**user_args)

        logger.info(f"Firebase user created: {firebase_user.uid}")

        return {
            'uid': firebase_user.uid,
            'email': firebase_user.email,
            'display_name': firebase_user.display_name,
            'disabled': firebase_user.disabled,
            'created_at': firebase_user.user_metadata.creation_timestamp
        }

    except Exception as e:
        logger.error(f"Failed to create Firebase user {email}: {str(e)}")
        raise Exception(f"Firebase user creation failed: {str(e)}")

def delete_user(firebase_uid: str) -> bool:
    """
    Delete a user from Firebase Auth.

    Args:
        firebase_uid: Firebase user UID to delete

    Returns:
        bool: True if deletion successful

    Raises:
        Exception: If Firebase user deletion fails
    """
    try:
        firebase_auth.delete_user(firebase_uid)
        logger.info(f"Firebase user deleted: {firebase_uid}")
        return True

    except Exception as e:
        logger.error(f"Failed to delete Firebase user {firebase_uid}: {str(e)}")
        raise Exception(f"Firebase user deletion failed: {str(e)}")

