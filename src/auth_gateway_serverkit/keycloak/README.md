# Keycloak Module

## File Map

| File | Description |
|---|---|
| `client.py` | Client token operations (retrieve, refresh, revoke), admin token, client CRUD, scopes, protocol mappers |
| `realm.py` | Realm management (create realm, frontend URL, edit username setting) |
| `role.py` | Role queries (get all, get by name, management permissions) and realm role creation |
| `authorization.py` | Authorization resources, policies, permissions (CRUD + cleanup) |
| `user.py` | User CRUD in Keycloak, role assignment, execute actions email |
| `initializer.py` | Full Keycloak server initialization flow (connection, setup, JSON config processing) |
| `config.py` | Pydantic settings for Keycloak connection |
| `utils.py` | Helper utilities (dynamic permission naming) |
