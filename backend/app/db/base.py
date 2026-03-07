from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# Force model imports so metadata registers tables
from app.models import *  # noqa
