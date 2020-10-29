import os
import uuid
from random import choice
import operator
from incountry import StorageServerException, Storage, RecordListForBatch
import sure  # noqa: F401
import pytest
from typing import Dict, List, Any
from datetime import datetime, timezone
from time import sleep

from ..utils import get_valid_test_record, get_test_records

COUNTRY = os.environ.get("INT_INC_COUNTRY")


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize(
    "data",
    [get_valid_test_record(), {"body": uuid.uuid4().hex, "profile_key": uuid.uuid4().hex}, {}],
    ids=["all the fields in record", "record_key, body, profile_key in record", "only record_key in record"],
)
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
@pytest.mark.parametrize("record_key", [uuid.uuid4().hex])
def test_write_record(
    storage: Storage,
    encrypt: bool,
    use_oauth: bool,
    data: Dict[str, Any],
    record_key: str,
    clean_up_records: None,
) -> None:
    data["record_key"] = record_key
    write_response = storage.write(country=COUNTRY, **data)
    write_response.should_not.be.none
    write_response.should.have.key("record")
    write_response["record"].should.be.equal(data)


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("record_key", [uuid.uuid4().hex])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_read_record(storage: Storage, encrypt: bool, use_oauth: bool, record_key: str, clean_up_records: None) -> None:
    record = get_valid_test_record()
    record["record_key"] = record_key
    storage.write(country=COUNTRY, **record)

    read_response = storage.read(country=COUNTRY, record_key=record_key)
    read_response.should.be.a("dict")
    read_response.should.have.key("record")
    for field in record:
        read_response["record"][field].should.be.equal(record[field])


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("record_key", [uuid.uuid4().hex])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_read_record_dates_with_update(
    storage: Storage, encrypt: bool, use_oauth: bool, record_key: str, clean_up_records: None
) -> None:
    record = get_valid_test_record()
    record["record_key"] = record_key
    start = datetime.now(tz=timezone.utc).replace(microsecond=0)
    storage.write(country=COUNTRY, **record)

    read_response = storage.read(country=COUNTRY, record_key=record_key)
    read_response.should.be.a("dict")
    read_response.should.have.key("record")
    for field in record:
        read_response["record"][field].should.be.equal(record[field])
    assert read_response["record"]["created_at"] >= start
    assert read_response["record"]["updated_at"] >= start

    sleep(1)
    record = get_valid_test_record()
    record["record_key"] = record_key
    storage.write(country=COUNTRY, **record)
    read_response2 = storage.read(country=COUNTRY, record_key=record_key)
    for field in record:
        read_response2["record"][field].should.be.equal(record[field])

    assert read_response2["record"]["created_at"] == read_response["record"]["created_at"]
    assert read_response2["record"]["updated_at"] > start
    assert read_response2["record"]["updated_at"] > read_response["record"]["updated_at"]


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_read_not_existing_record(storage: Storage, encrypt: bool, use_oauth: bool) -> None:
    record_key = uuid.uuid4().hex
    storage.read.when.called_with(country=COUNTRY, record_key=record_key).should.have.raised(StorageServerException)


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_delete_record(storage: Storage, encrypt: bool, use_oauth: bool) -> None:
    record_key = uuid.uuid4().hex

    storage.write(country=COUNTRY, record_key=record_key, body="some body")

    r = storage.read(country=COUNTRY, record_key=record_key)
    assert r is not None

    delete_response = storage.delete(country=COUNTRY, record_key=record_key)
    delete_response.should.be.a("dict")
    delete_response.should.have.key("success")
    delete_response["success"].should.be(True)

    storage.read.when.called_with(country=COUNTRY, record_key=record_key).should.have.raised(StorageServerException)
    storage.delete.when.called_with(country=COUNTRY, record_key=record_key).should.have.raised(StorageServerException)


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_delete_not_existing_record(storage: Storage, encrypt: bool, use_oauth: bool) -> None:
    record_key = uuid.uuid4().hex
    storage.delete.when.called_with(country=COUNTRY, record_key=record_key).should.have.raised(StorageServerException)


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("record_key", [[uuid.uuid4().hex for _ in range(3)]])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_batch_write_records(
    storage: Storage, encrypt: bool, use_oauth: bool, record_key: List[str], clean_up_records: None
) -> None:
    records = get_test_records()[-3:]
    for i, key in enumerate(record_key):
        records[i]["record_key"] = record_key[i]

    written = storage.batch_write(country=COUNTRY, records=records)

    written.should.be.a("dict")
    written.should.have.key("records")
    written["records"].should.be.a("list")
    written["records"].should.equal(RecordListForBatch(records=records).records)


@pytest.mark.parametrize("normalize_keys", [True, False], ids=["with normalized keys", "with non-normalized keys"])
@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_by_one_key(
    storage: Storage,
    encrypt: bool,
    use_oauth: bool,
    normalize_keys: bool,
    expected_records: List[Dict[str, Any]],
) -> None:
    keys_to_search = filter(lambda key: key not in ["body", "precommit_body"], get_valid_test_record().keys())
    for key in keys_to_search:
        key_value = choice(expected_records)[key]
        if normalize_keys and isinstance(key_value, str):
            key_value.should.equal(key_value.upper())
        elif normalize_keys:
            continue

        print(f"Find by {key}{' with normalization' if normalize_keys else ''}.")
        search = {key: key_value}
        find_result = storage.find(country=COUNTRY, **search)
        find_result.should.be.a("dict")
        find_result.should.have.key("records")
        find_result.should.have.key("meta")
        actual_keys = [record[key] for record in find_result["records"]]
        expected_keys = [record[key] for record in expected_records if record[key] == key_value]
        expected_keys.should.equal(actual_keys)


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_by_one_key_with_not(
    storage: Storage,
    encrypt: bool,
    use_oauth: bool,
    expected_records: List[Dict[str, Any]],
) -> None:
    keys_to_search = list(
        filter(
            lambda key: "range_key" not in key and key not in ["record_key", "body", "precommit_body"],
            get_valid_test_record().keys(),
        )
    )
    for key in keys_to_search:
        print("Find by one key with $not - ", key)
        key_value = choice(expected_records)[key]
        search = {key: {"$not": key_value}, "record_key": [record["record_key"] for record in expected_records]}
        find_result = storage.find(country=COUNTRY, **search)
        find_result.should.be.a("dict")
        find_result.should.have.key("records")
        find_result.should.have.key("meta")
        actual_keys = [record[key] for record in find_result["records"]]
        expected_keys = [record[key] for record in expected_records if record[key] != key_value]
        assert set(expected_keys) == set(actual_keys)


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_by_one_key_with_not_for_key(
    storage: Storage,
    encrypt: bool,
    use_oauth: bool,
    expected_records: List[Dict[str, Any]],
) -> None:
    keys_to_search = list(
        filter(
            lambda key: "range_key" not in key and key not in ["record_key", "body", "precommit_body"],
            get_valid_test_record().keys(),
        )
    )
    for key in keys_to_search:
        print(f"Find by {key} with $not for record key")
        key_value = choice(expected_records)["record_key"]
        search = {"record_key": {"$not": key_value}, key: [record[key] for record in expected_records]}
        find_result = storage.find(country=COUNTRY, **search)
        find_result.should.be.a("dict")
        find_result.should.have.key("records")
        find_result.should.have.key("meta")
        actual_keys = [record["record_key"] for record in find_result["records"]]
        expected_keys = [record["record_key"] for record in expected_records if record["record_key"] != key_value]
        assert set(expected_keys) == set(actual_keys)


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_by_list_of_keys(
    storage: Storage,
    encrypt: bool,
    use_oauth: bool,
    expected_records: List[Dict[str, Any]],
) -> None:
    keys_to_search = filter(lambda key: key not in ["body", "precommit_body"], get_valid_test_record().keys())
    for key in keys_to_search:
        print(f"Find by list of keys - {key}")
        key_values = [record[key] for record in expected_records]
        search = {key: key_values}
        find_result = storage.find(country=COUNTRY, **search)
        find_result.should.be.a("dict")
        find_result.should.have.key("records")
        find_result.should.have.key("meta")
        actual_keys = {record[key] for record in find_result["records"]}
        expected_keys = {record[key] for record in expected_records}
        expected_keys.should.equal(actual_keys)


@pytest.mark.parametrize("range_operator", ["$gt", "$lt", "$gte", "$lte"])
@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_by_range_key_gt_lt(
    storage: Storage, encrypt: bool, use_oauth: bool, expected_records: List[Dict[str, Any]], range_operator: str
) -> None:
    record_keys = [record["record_key"] for record in expected_records]
    op = {
        "$gt": operator.gt,
        "$gte": operator.ge,
        "$lt": operator.lt,
        "$lte": operator.le,
    }

    keys_to_search = filter(lambda key: "range_key" in key, get_valid_test_record().keys())
    for key in keys_to_search:
        print(f"Find by range key gt/lt - {key}, operator {range_operator}")

        middle_value_record = sorted(expected_records, key=lambda record: record[key])[int(len(expected_records) / 2)]

        search = {key: {range_operator: middle_value_record[key]}}
        find_result = storage.find(country=COUNTRY, record_key=record_keys, **search)

        actual_records = find_result["records"]
        expected_key_values = set(
            [
                record[key]
                for record in filter(lambda r: op[range_operator](r[key], middle_value_record[key]), expected_records)
            ]
        )

        len(actual_records).should.be.greater_than(0)
        assert expected_key_values == set([record[key] for record in actual_records])


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_not_existing_record(
    storage: Storage,
    encrypt: bool,
    use_oauth: bool,
) -> None:
    find_nothing = storage.find(country=COUNTRY, record_key="Not existing key")
    len(find_nothing["records"]).should.be.equal(0)
    find_nothing["meta"]["total"].should.be.equal(0)


@pytest.mark.parametrize("number_of_records", [10])
@pytest.mark.parametrize(
    "limit",
    [1, 5, 10],
    ids=["limit_1", "limit_5", "limit_10"],
)
@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_limit_works(
    encrypt: bool,
    use_oauth: bool,
    storage: Storage,
    limit: int,
    expected_records: List[Dict[str, Any]],
    number_of_records: int,
) -> None:
    record_keys = [record["record_key"] for record in expected_records]

    find_limit = storage.find(country=COUNTRY, record_key=record_keys, limit=limit)
    find_limit["meta"]["limit"].should.be.equal(limit)
    len(find_limit["records"]).should.be.equal(limit)
    found_keys = [record["record_key"] for record in find_limit["records"]]
    assert set(found_keys).issubset(set(record_keys))


@pytest.mark.parametrize("number_of_records", [10])
@pytest.mark.parametrize(
    "offset",
    [0, 1, 10],
    ids=["offset_0", "offset_1", "offset_10"],
)
@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_offset_works(
    encrypt: bool,
    use_oauth: bool,
    storage: Storage,
    offset: int,
    expected_records: List[Dict[str, Any]],
    number_of_records: int,
) -> None:
    record_keys = [record["record_key"] for record in expected_records]
    remains_after_offset = max(10 - offset, 0)

    find_offset = storage.find(country=COUNTRY, record_key=record_keys, offset=offset)
    len(find_offset["records"]).should.be.equal(remains_after_offset)
    find_offset["meta"]["offset"].should.be.equal(offset)
    found_keys = [record["record_key"] for record in find_offset["records"]]
    assert set(found_keys).issubset(set(record_keys))


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_one(
    storage: Storage,
    encrypt: bool,
    use_oauth: bool,
    expected_records: List[Dict[str, Any]],
) -> None:
    keys_to_search = filter(lambda key: key not in ["body", "precommit_body"], get_valid_test_record().keys())

    for key in keys_to_search:
        print(f"Find one by {key}.")

        key_value = choice(expected_records)[key]

        search = {key: key_value}
        find_one_record = storage.find_one(country=COUNTRY, **search)
        find_one_record.should_not.be.none
        find_one_record.should.be.a("dict")
        find_one_record.should.have.key("record")
        find_one_record["record"][key].should.be.equal(key_value)


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
def test_find_one_empty_response(
    storage: Storage,
    encrypt: bool,
    use_oauth: bool,
) -> None:
    r = storage.find_one(country=COUNTRY, record_key=uuid.uuid4().hex)
    r.should.equal(None)
