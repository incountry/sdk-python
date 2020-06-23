from typing import List, Dict
import re
import os
import sure  # noqa: F401
import pytest
from incountry import (
    StorageClientException,
    StorageServerException,
    Storage,
    SecretKeyAccessor,
)

API_KEY = os.environ.get("INT_INC_API_KEY")
ENV_ID = os.environ.get("INT_INC_ENVIRONMENT_ID")
ENDPOINT = os.environ.get("INT_INC_ENDPOINT")
COUNTRY = os.environ.get("INT_INC_COUNTRY")


@pytest.mark.parametrize("encrypt", [False], ids=["not encrypted"])
def test_migrate_should_raise_error_without_encryption(storage: Storage, encrypt: bool) -> None:

    storage.migrate.when.called_with(country=COUNTRY).should.have.raised(
        StorageClientException, re.compile(r"This method is only allowed with encryption enabled"),
    )


@pytest.mark.xfail(Reason="Works only for storage with encrypted records")
@pytest.mark.parametrize("encrypt", [True], ids=["encrypted"])
def test_migrate_works_with_encryption(storage: Storage, encrypt: bool, expected_records: List[Dict]) -> None:
    keys = {record["key"] for record in expected_records}
    find_all = storage.find(country=COUNTRY)
    all_records = find_all["meta"]["total"]

    # There are records with ver 2, let's create storage with different version
    secrets_data = {
        "currentVersion": 3,
        "secrets": [{"secret": "new super secret", "version": 3}, {"secret": "super secret", "version": 2}],
    }
    new_storage = Storage(
        encrypt=True,
        debug=True,
        api_key=API_KEY,
        environment_id=ENV_ID,
        endpoint=ENDPOINT,
        secret_key_accessor=SecretKeyAccessor(lambda: secrets_data),
    )

    migration_result = new_storage.migrate(country=COUNTRY)
    migration_result.should.have.key("migrated")
    migration_result.should.have.key("total_left")
    migration_result["migrated"].should.be.a("int")
    migration_result["total_left"].should.be.a("int")
    all_records.should.be.greater_than_or_equal_to(migration_result["migrated"])

    nothing_lost = new_storage.find(country=COUNTRY)
    found_keys = {record["key"] for record in nothing_lost["data"]}
    keys.should.be.equal(found_keys)
    nothing_lost["meta"]["total"].should.be.equal(all_records)

    read_record = new_storage.read(country=COUNTRY, key=expected_records[0]["key"])
    for key in expected_records[0]:
        read_record["record"][key].should.be.equal(expected_records[0][key])
    read_record["record"]["version"].should.be.equal(secrets_data["currentVersion"])
    storage.read.when.called_with(country=COUNTRY, key=expected_records[0]["key"]).should.have.raised(
        StorageServerException
    )
