from functools import wraps
from auth_gateway_serverkit.logger import init_logger

logger = init_logger("serverkit.middleware.rbac")
def require_roles(*allowed_roles: str):
    """
    Decorator to check if the user has the required roles to access a function.

    Args:
        *allowed_roles: List of role names that are allowed to access the function

    Usage:
        @require_roles("admin", "systemAdmin")
        async def some_function(data, request_user=None):
            # Function implementation
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(data, request_user=None, *args, **kwargs):
            if not request_user:
                logger.warning(f"Unauthorized access attempt to {func.__name__} without request_user")
                raise Exception(f"unauthorized access")

            user_roles = request_user.get("roles", [])
            if not user_roles:
                logger.warning(
                    f"User {request_user.get('id')} has no roles and attempted to access {func.__name__} which requires roles: {allowed_roles}")
                raise Exception(f"unauthorized access")

            # Check if user has any of the required roles
            has_required_role = any(role in allowed_roles for role in user_roles)

            if not has_required_role:
                logger.warning(
                    f"User {request_user.get('id')} with roles {user_roles} attempted to access {func.__name__} which requires roles: {allowed_roles}")
                raise Exception(f"unauthorized access")

            # User has required role, proceed with function execution
            return await func(data, request_user, *args, **kwargs)

        return wrapper

    return decorator