from sqlalchemy import BigInteger, Integer
from sqlalchemy.orm import DeclarativeBase

# BIGINT primary keys; SQLite (unit tests) only auto-increments INTEGER.
BigIntegerPK = BigInteger().with_variant(Integer(), "sqlite")


class Base(DeclarativeBase):
    pass
