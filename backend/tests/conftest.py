from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from app.db import make_engine, session_factory
from app.main import create_app
from app.schemas import AssessmentCreate, Configuration, ScopeInput
from app.services import assessments


@pytest.fixture
def engine(tmp_path):
    url = f"sqlite:///{tmp_path / 'test.db'}"
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).parents[1] / "alembic"))
    config.attributes["database_url"] = url
    command.upgrade(config, "head")
    engine = make_engine(url)
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine):
    with session_factory(engine)() as db:
        yield db


@pytest.fixture
def client(engine):
    with TestClient(
        create_app(engine), headers={"X-WebScope-Request": "workstation", "Content-Type": "application/json"}
    ) as client:
        yield client


@pytest.fixture
def make_assessment(db):
    def make(target="http://127.0.0.1:9998", **config):
        from urllib.parse import urlsplit

        item = assessments.create(
            db,
            AssessmentCreate(
                name="Fixture assessment",
                target=target,
                authorized=True,
                authorization_note="I own this local synthetic fixture and authorize these read-only checks.",
                scope=ScopeInput(
                    allowed_hosts=[urlsplit(target).hostname], excluded_paths=["/admin", "/payments"]
                ),
                config=Configuration(
                    mode="SAFE_HTTP", allow_private_network=True, rate_per_second=10, tls=False, **config
                ),
            ),
        )
        assessments.validate(db, item)
        db.commit()
        return item

    return make


@pytest.fixture
def payload():
    return {
        "name": "Local fixture",
        "target": "http://127.0.0.1:9998",
        "scope": {"allowed_hosts": ["127.0.0.1"], "excluded_paths": ["/admin"]},
        "authorized": True,
        "authorization_note": "I own this loopback fixture.",
        "config": {"mode": "SAFE_HTTP", "allow_private_network": True, "rate_per_second": 10, "tls": False},
    }
