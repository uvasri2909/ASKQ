"""The schema description given to the model, filtered by the user's role.

Deterministic and application-controlled: built from catalog.py and the role
policy, never by querying the database. A role sees only the tables it may
query and never sees its hidden columns. users, roles and askq_system are
not in the catalog, so no user ever sees them described. This is for
usefulness only; authorization.py enforces the same policy on the SQL.
"""

from app.query.catalog import TABLES
from app.query.policy import policy_for
from app.rbac.roles import Role


def schema_context(role: Role) -> str:
    policy = policy_for(role)
    lines = []
    for table in TABLES:
        if table.name not in policy.tables:
            continue
        hidden = policy.hidden_columns(table.name)
        kind = "VIEW" if table.is_view else "TABLE"
        note = " Rows are limited to your scope." if table.name in policy.row_scope else ""
        lines.append(f"{kind} {table.name}: {table.description}{note}")
        for column in table.columns:
            if column.name in hidden:
                continue
            description = f"  -- {column.description}" if column.description else ""
            lines.append(f"  {column.name} {column.type}{description}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
