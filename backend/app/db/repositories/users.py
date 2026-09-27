from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Department, User


def get_by_username(session: Session, username: str) -> User | None:
    return session.scalars(select(User).where(User.username == username)).one_or_none()


def get_by_id(session: Session, user_id: int) -> User | None:
    return session.get(User, user_id)


def department_headed_by(session: Session, teacher_id: int) -> int | None:
    """The department whose head is this teacher (unique in the schema), if any."""
    return session.scalars(
        select(Department.department_id).where(Department.head_teacher_id == teacher_id)
    ).one_or_none()
