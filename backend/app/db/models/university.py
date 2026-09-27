"""askq_university tables that askq_app may read (users, roles, departments)."""

from sqlalchemy import Boolean, ForeignKey, Integer, SmallInteger, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.engine import UNIVERSITY_SCHEMA
from app.db.models.base import Base


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = {"schema": UNIVERSITY_SCHEMA}

    role_id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=False)
    role_code: Mapped[str] = mapped_column(String(20), unique=True)
    role_name: Mapped[str] = mapped_column(String(50))


class Department(Base):
    __tablename__ = "departments"
    __table_args__ = {"schema": UNIVERSITY_SCHEMA}

    department_id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    department_code: Mapped[str] = mapped_column(String(10), unique=True)
    department_name: Mapped[str] = mapped_column(String(100))
    # teachers is not granted to askq_app, so this stays a plain column.
    head_teacher_id: Mapped[int | None] = mapped_column(Integer, unique=True)


class User(Base):
    """A login identity. Holds no secrets; see AppUserCredential."""

    __tablename__ = "users"
    __table_args__ = {"schema": UNIVERSITY_SCHEMA}

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    role_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey(Role.role_id))
    teacher_id: Mapped[int | None] = mapped_column(Integer, unique=True)
    student_id: Mapped[int | None] = mapped_column(Integer, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean)

    role: Mapped[Role] = relationship(lazy="joined", innerjoin=True)
