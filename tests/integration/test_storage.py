import os
import pytest
import uuid
from pytest_testrail.plugin import pytestrail
from incountry import SecretKeyAccessor, Storage

API_KEY = os.environ.get("INT_INC_API_KEY")
ENVIRONMENT_ID = os.environ.get("INT_INC_ENVIRONMENT_ID")
ENDPOINT = os.environ.get("INT_INC_ENDPOINT")
SECRETS_DATA = {
    "secrets": [{"secret": "supersecret", "version": 2}],
    "currentVersion": 2,
}


@pytest.fixture()
def client():
    # env should contain: INC_ENV_ID and INC_API_KEY)
    yield Storage(
        encrypt=True,
        debug=True,
        api_key=API_KEY,
        environment_id=ENVIRONMENT_ID,
        endpoint=ENDPOINT,
        secret_key_accessor=SecretKeyAccessor(lambda: SECRETS_DATA),
    )


@pytestrail.case("C143")
def test_write_single_pop(client):
    key1 = uuid.uuid4().hex
    client.write(country="us", key=key1)
    r = client.read(country="us", key=key1)
    assert r is not None
    assert "version" in r
    assert r["key"] == key1


@pytestrail.case("C144")
def test_read_single_pop(client):
    key1 = uuid.uuid4().hex
    key2 = uuid.uuid4().hex

    client.write(country="us", key=key1, body="Welcome to Florence")
    client.write(country="us", key=key2, body="Welcome to Rome")

    r = client.read(country="us", key=key1)
    assert r["body"] == "Welcome to Florence"

    r = client.read(country="us", key=key2)
    assert r["body"] == "Welcome to Rome"


@pytestrail.case("C147")
def test_delete_single_pop(client):
    key1 = uuid.uuid4().hex

    client.write(country="us", key=key1, body="Konichiwa")
    r = client.read(country="us", key=key1)
    assert r is not None

    client.delete(country="us", key=key1)

    r = client.read(country="us", key=key1)
    assert r is None


# @pytestrail.case("C148")
# def test_using_encryption():
#     key1 = uuid.uuid4().hex

#     eclient = Storage(
#         api_key=API_KEY,
#         environment_id=ENVIRONMENT_ID,
#         endpoint=ENDPOINT,
#         encrypt=True,
#         secret_key_accessor=SecretKeyAccessor(lambda: SECRETS_DATA),
#     )
#     eclient.write(country="us", key=key1, body="You cant read this text")

#     client = Storage(
#         api_key=API_KEY,
#         environment_id=ENVIRONMENT_ID,
#         endpoint=ENDPOINT,
#         encrypt=False,
#         secret_key_accessor=SecretKeyAccessor(lambda: SECRETS_DATA),
#     )
#     # Keys won't clash because of encryption
#     client.write(country="us", key=key1, body="You CAN read this text")

#     r = eclient.read(country="us", key=key1)
#     assert r["body"] == "You cant read this text"

#     r = client.read(country="us", key=key1)
#     assert r["body"] == "You CAN read this text"