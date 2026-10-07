import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


def make_engine(url: str):
    engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def configure(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA secure_delete=ON")

    return engine


def database_url():
    path = Path(os.environ.get("WEBSCOPE_DATA_DIR", "../data")).resolve()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return os.environ.get("WEBSCOPE_DATABASE_URL", f"sqlite:///{path / 'webscope.db'}")


def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)
