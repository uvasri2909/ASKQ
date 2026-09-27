"""Role-based access control.

* roles.py        the four roles (ids pinned by roles.ck_roles_id_code in Phase 2)
* permissions.py  WHAT a role may do (features), in one table
* scope.py        WHICH rows a user may see (data scope), and the UserContext
* dependencies.py reusable FastAPI guards (require_roles, require_permission, ...)

A UserContext is built only on the server, from the database, for each
request. Nothing supplied by the client (request body, query string, headers,
token claims, or later conversation context) can change a user's role or scope.
"""
