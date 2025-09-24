"""firebase server initialization module for the auth gateway serverkit."""

import firebase_admin
from firebase_admin import auth as firebase_auth
from ..logger import init_logger


logger = init_logger("serverkit.firebase.initializer")

def initialize_firebase():
    """Initialize Firebase Admin SDK if not already initialized."""
    try:
        if not firebase_admin._apps:
            # Initialize Firebase with default credentials (Google Cloud CLI)
            firebase_admin.initialize_app()
            logger.info("Firebase Admin SDK initialized with default credentials")
    except Exception as ex:
        logger.error(f"Failed to initialize Firebase Admin SDK: {str(ex)}")
        raise