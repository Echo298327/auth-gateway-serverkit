"""Utility functions for Keycloak integration in the auth gateway serverkit."""


def create_dynamic_permission_name(policies):
    """
    Create a clean, short permission name from any policy names dynamically.
    Works with any policy naming convention without hardcoding.
    """
    if len(policies) == 1:
        # Single policy: remove common suffixes and make it clean
        name = policies[0]
        # Remove common suffixes like "-Access", "-Policy", etc.
        for suffix in ['-Access', '-Policy', '-Permission', '_Access', '_Policy', '_Permission']:
            name = name.replace(suffix, '')
        # Convert to lowercase and replace underscores with dashes
        name = name.replace('_', '-').lower()
        return name
    else:
        # Multiple policies: combine them cleanly
        clean_names = []
        for policy in sorted(policies):  # Sort for consistency
            name = policy
            # Remove common suffixes
            for suffix in ['-Access', '-Policy', '-Permission', '_Access', '_Policy', '_Permission']:
                name = name.replace(suffix, '')
            # Convert to lowercase and replace underscores with dashes
            name = name.replace('_', '-').lower()
            clean_names.append(name)
        return '-'.join(clean_names)
