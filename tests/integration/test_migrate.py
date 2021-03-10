from typing import List, Dict
import re
import os
import sure  # noqa: F401
import pytest
import copy
from incountry import (
    StorageClientException,
    Storage,
    SecretKeyAccessor,
    InCrypto,
)

API_KEY = os.environ.get("INT_INC_API_KEY")
ENV_ID = os.environ.get("INT_INC_ENVIRONMENT_ID")
ENDPOINT = os.environ.get("INT_INC_ENDPOINT")
COUNTRY = os.environ.get("INT_INC_COUNTRY")


@pytest.mark.parametrize("encrypt", [False], ids=["not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_migrate_should_raise_error_without_encryption(storage: Storage, encrypt: bool, use_oauth: bool) -> None:

    storage.migrate.when.called_with(country=COUNTRY).should.have.raised(
        StorageClientException,
        re.compile(r"This method is only allowed with encryption enabled"),
    )


@pytest.mark.parametrize("encrypt", [True], ids=["encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_migrate_works_with_encryption(
    storage: Storage, encrypt: bool, use_oauth: bool, expected_records: List[Dict]
) -> None:
    limit = 3
    find_all = storage.find(country=COUNTRY, version={"$not": 4}, limit=1)
    total_records_with_non_4_version = find_all["meta"]["total"]

    # There are records with ver 2, let's create storage with different version
    secrets_data = {
        "currentVersion": 4,
        "secrets": [
            {"secret": "super secret", "version": 2},
            {"secret": b"3" * 32, "isKey": True, "version": 3},
            {"secret": b"4" * 32, "isKey": True, "version": 4},
        ],
    }

    new_storage = copy.deepcopy(storage)
    new_storage.crypto = InCrypto(SecretKeyAccessor(lambda: secrets_data))

    migration_result = new_storage.migrate(country=COUNTRY, limit=limit)
    migration_result.should.have.key("migrated")
    migration_result.should.have.key("total_left")
    migration_result["migrated"].should.be.a("int")
    migration_result["total_left"].should.be.a("int")
    total_records_with_non_4_version.should.be.greater_than_or_equal_to(migration_result["migrated"])

    records_with_version_4 = new_storage.find(country=COUNTRY, version=4)
    records_with_version_4["meta"]["total"].should.be.greater_than_or_equal_to(migration_result["migrated"])
