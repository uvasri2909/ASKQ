from enum import StrEnum


class Role(StrEnum):
    ADMIN = "ADMIN"
    HOD = "HOD"
    TEACHER = "TEACHER"
    STUDENT = "STUDENT"


# Fixed by roles.ck_roles_id_code in database/schema/02_university_schema.sql.
ROLE_IDS: dict[Role, int] = {Role.ADMIN: 1, Role.HOD: 2, Role.TEACHER: 3, Role.STUDENT: 4}


def role_from_database(role_id: int, role_code: str) -> Role | None:
    """The Role for a roles row, or None if the row is not one of the four pinned roles."""
    try:
        role = Role(role_code)
    except ValueError:
        return None
    return role if ROLE_IDS[role] == role_id else None
