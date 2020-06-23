from incountry import SecretKeyAccessor, Storage
import os
import pytest
from random import randint
from typing import Any, List, Dict, Generator, Union
import uuid

API_KEY = os.environ.get("INT_INC_API_KEY")
ENVIRONMENT_ID = os.environ.get("INT_INC_ENVIRONMENT_ID")
ENDPOINT = os.environ.get("INT_INC_ENDPOINT")
COUNTRY = os.environ.get("INT_INC_COUNTRY")
SECRETS_DATA = {
    "secrets": [{"secret": "super secret", "version": 2}],
    "currentVersion": 2,
}


@pytest.fixture
def storage(encrypt: bool) -> Storage:
    """Creating storage"""
    secret_key_accessor = SecretKeyAccessor(lambda: SECRETS_DATA)

    if encrypt:
        storage = Storage(
            encrypt=True,
            debug=True,
            api_key=API_KEY,
            environment_id=ENVIRONMENT_ID,
            endpoint=ENDPOINT,
            secret_key_accessor=secret_key_accessor,
        )
    else:
        storage = Storage(encrypt=False, debug=True, api_key=API_KEY, environment_id=ENVIRONMENT_ID, endpoint=ENDPOINT)

    yield storage


def create_records(number_of_records: int) -> List[Dict]:
    return [
        {
            "key": uuid.uuid4().hex,
            "key2": uuid.uuid4().hex,
            "key3": uuid.uuid4().hex,
            "profile_key": uuid.uuid4().hex,
            "range_key": randint(-(2 ** 63), 2 ** 63 - 1),
            "body": uuid.uuid4().hex,
        }
        for _ in range(number_of_records)
    ]


@pytest.fixture(autouse=True)
def number_of_records() -> int:
    yield 3


@pytest.fixture
def expected_records(
    storage: Storage, number_of_records: int, country: str = COUNTRY
) -> Generator[List[Dict[str, Any]], None, None]:
    data = create_records(number_of_records)
    for record in data:
        assert "key" in record.keys()
        response = storage.write(country=country, **record)
        assert response["record"]["key"] == record["key"]
    yield data

    for record in data:
        key = record["key"]
        response = storage.delete(country=country, key=key)
        assert response == {"success": True}


@pytest.fixture
def clean_up_records(
    storage: Storage, key: Union[List[str], str], country: str = COUNTRY
) -> Generator[None, None, None]:
    yield
    if isinstance(key, list):
        for k in key:
            deletion = storage.delete(country=country, key=k)
            assert deletion == {"success": True}
    elif isinstance(key, str):
        deletion = storage.delete(country=country, key=key)
        assert deletion == {"success": True}
