from incountry import SecretKeyAccessor, Storage
import os
import pytest
from random import randint
from typing import Any, List, Dict, Generator, Union
import uuid

API_KEY = os.environ.get("INT_INC_API_KEY")
ENVIRONMENT_ID = os.environ.get("INT_INC_ENVIRONMENT_ID")

CLIENT_ID = os.environ.get("INT_INC_CLIENT_ID")
CLIENT_SECRET = os.environ.get("INT_INC_CLIENT_SECRET")
ENVIRONMENT_ID_OAUTH = os.environ.get("INT_INC_ENVIRONMENT_ID_OAUTH")
OAUTH_ENDPOINT = os.environ.get("INT_INC_DEFAULT_AUTH_ENDPOINT")
COUNTRIES_LIST_ENDPOINT = os.environ.get("INT_COUNTRIES_LIST_ENDPOINT")

ENDPOINT = os.environ.get("INT_INC_ENDPOINT")
COUNTRY = os.environ.get("INT_INC_COUNTRY")

SECRETS_DATA = {
    "secrets": [
        {"secret": "super secret", "version": 2},
        {"secret": b"3" * 32, "version": 3},
    ],
    "currentVersion": 3,
}


@pytest.fixture
def storage(encrypt: bool, normalize_keys: bool, use_oauth: bool, hash_search_keys: bool) -> Storage:
    args = {
        "encrypt": encrypt,
        "debug": True,
        "api_key": API_KEY,
        "environment_id": ENVIRONMENT_ID,
        "endpoint": ENDPOINT,
        "options": {
            "normalize_keys": normalize_keys,
            "countries_endpoint": COUNTRIES_LIST_ENDPOINT,
            "hash_search_keys": True if hash_search_keys is None else hash_search_keys,
        },
    }

    if use_oauth:
        args["client_id"] = CLIENT_ID
        args["client_secret"] = CLIENT_SECRET
        args["environment_id"] = ENVIRONMENT_ID_OAUTH
        args["options"]["auth_endpoints"] = {"default": OAUTH_ENDPOINT}
        del args["api_key"]

    if encrypt:
        args["secret_key_accessor"] = SecretKeyAccessor(lambda: SECRETS_DATA)

    storage = Storage(**args)

    yield storage


def create_records(number_of_records: int, uppercase_values: bool = False) -> List[Dict]:
    def gen_value():
        return uuid.uuid4().hex.upper() if uppercase_values else uuid.uuid4().hex

    return [
        {
            "record_key": gen_value(),
            "profile_key": gen_value(),
            "service_key1": gen_value(),
            "service_key2": gen_value(),
            "key1": gen_value(),
            "key2": gen_value(),
            "key3": gen_value(),
            "key4": gen_value(),
            "key5": gen_value(),
            "key6": gen_value(),
            "key7": gen_value(),
            "key8": gen_value(),
            "key9": gen_value(),
            "key10": gen_value(),
            "range_key1": randint(-(2 ** 63), 2 ** 63 - 1),
            "range_key2": randint(-(2 ** 63), 2 ** 63 - 1),
            "range_key3": randint(-(2 ** 63), 2 ** 63 - 1),
            "range_key4": randint(-(2 ** 63), 2 ** 63 - 1),
            "range_key5": randint(-(2 ** 63), 2 ** 63 - 1),
            "range_key6": randint(-(2 ** 63), 2 ** 63 - 1),
            "range_key7": randint(-(2 ** 63), 2 ** 63 - 1),
            "range_key8": randint(-(2 ** 63), 2 ** 63 - 1),
            "range_key9": randint(-(2 ** 63), 2 ** 63 - 1),
            "range_key10": randint(-(2 ** 63), 2 ** 63 - 1),
            "body": gen_value(),
            "precommit_body": gen_value(),
        }
        for _ in range(number_of_records)
    ]


@pytest.fixture(autouse=True)
def number_of_records() -> int:
    yield 3


@pytest.fixture(autouse=True)
def normalize_keys() -> bool:
    yield False


@pytest.fixture(autouse=True)
def hash_search_keys() -> bool:
    yield True


@pytest.fixture
def expected_records(
    storage: Storage, number_of_records: int, normalize_keys: bool, country: str = COUNTRY
) -> Generator[List[Dict[str, Any]], None, None]:
    data = create_records(number_of_records, normalize_keys)
    for record in data:
        assert "record_key" in record.keys()
        response = storage.write(country=country, **record)
        assert response["record"]["record_key"] == record["record_key"]
    yield data

    for record in data:
        record_key = record["record_key"]
        response = storage.delete(country=country, record_key=record_key)
        assert response == {"success": True}


@pytest.fixture
def clean_up_records(
    storage: Storage, record_key: Union[List[str], str], country: str = COUNTRY
) -> Generator[None, None, None]:
    yield
    if isinstance(record_key, list):
        for k in record_key:
            deletion = storage.delete(country=country, record_key=k)
            assert deletion == {"success": True}
    elif isinstance(record_key, str):
        deletion = storage.delete(country=country, record_key=record_key)
        assert deletion == {"success": True}


@pytest.fixture
def tempfile(filename: str, filebody: str) -> Generator[None, None, None]:
    filepath = f"./{filename}"
    with open(filepath, "wb") as f:
        f.write(filebody)
        f.close()

    yield {"path": filepath}

    os.remove(filepath)
