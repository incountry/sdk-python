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
    find_all = storage.find(country=COUNTRY, version={"$not": 3})
    all_records_with_curr_version = find_all["meta"]["total"]

    # There are records with ver 2, let's create storage with different version
    secrets_data = {
        "currentVersion": 3,
        "secrets": [{"secret": "new super secret", "version": 3}, {"secret": "super secret", "version": 2}],
    }

    new_storage = copy.deepcopy(storage)
    new_storage.crypto = InCrypto(SecretKeyAccessor(lambda: secrets_data))

    migration_result = new_storage.migrate(country=COUNTRY, limit=limit)
    migration_result.should.have.key("migrated")
    migration_result.should.have.key("total_left")
    migration_result["migrated"].should.be.a("int")
    migration_result["total_left"].should.be.a("int")
    all_records_with_curr_version.should.be.greater_than_or_equal_to(migration_result["migrated"])

    records_after_migration = new_storage.find(country=COUNTRY, version={"$not": 3})

    assert records_after_migration["meta"]["total"] + migration_result["migrated"] == all_records_with_curr_version
    new_storage.find.when.called_with(country=COUNTRY, version=3, limit=limit).should_not.throw(Exception)
