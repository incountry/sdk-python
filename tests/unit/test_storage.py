import uuid
import json
import os
from datetime import datetime

import pytest
import sure  # noqa: F401
import httpretty
from cryptography.fernet import Fernet

from incountry import (
    Storage,
    StorageServerException,
    StorageClientException,
    SecretKeyAccessor,
    InCrypto,
    HttpClient,
    FindFilter,
    RecordListForBatch,
    get_salted_hash,
)

from ..utils import (
    omit,
    get_test_records,
    get_valid_find_filter_test_options,
    get_randomcase_record,
    get_random_str,
    get_random_datetime,
)

POPAPI_URL = "https://popapi.com:8082"
COUNTRY = "us"
SECRET_KEY = "password"

TEST_RECORDS = get_test_records()


def json_converter(o):
    if isinstance(o, datetime):
        return o.__str__()


def get_default_find_response(count, data, total=None):
    total = count if total is None else total
    return {
        "meta": {"total": total, "count": count, "limit": 100, "offset": 0},
        "data": data,
    }


def get_key_hash(key):
    return get_salted_hash(key, "test")


@pytest.fixture()
def client():
    def cli(
        encrypt=True,
        endpoint=POPAPI_URL,
        secret_accessor=SecretKeyAccessor(lambda: SECRET_KEY),
        custom_encryption=None,
        environment_id="test",
        **kwargs,
    ):
        return Storage(
            encrypt=encrypt,
            debug=True,
            environment_id=environment_id,
            api_key="test",
            endpoint=endpoint,
            secret_key_accessor=secret_accessor,
            custom_encryption_configs=custom_encryption,
            **kwargs,
        )

    return cli


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_write(client, record, encrypt):
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body="OK")

    write_res = client(encrypt).write(country=COUNTRY, **record)
    write_res.should.have.key("record")
    assert record.items() <= write_res["record"].items()

    received_record = json.loads(httpretty.last_request().body)

    for key, value in record.items():
        if isinstance(value, int):
            assert received_record[key] == record[key]
        else:
            assert received_record[key] != record[key]


@httpretty.activate
@pytest.mark.parametrize("record", get_test_records(use_last_field_value=True, last_field_value=None)[1:])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_write_with_none_fields(client, record, encrypt):
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body="OK")

    write_res = client(encrypt).write(country=COUNTRY, **record)
    write_res.should.have.key("record")
    assert record.items() > write_res["record"].items()

    received_record = json.loads(httpretty.last_request().body)

    for key, value in record.items():
        if value is None and key != "body":
            assert key not in received_record
        elif isinstance(value, int):
            assert received_record[key] == record[key]
        else:
            assert received_record[key] != record[key]


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.parametrize("keys_data", [{"currentVersion": 1, "secrets": [{"secret": SECRET_KEY, "version": 1}]}])
@pytest.mark.happy_path
def test_write_with_keys_data(client, record, encrypt, keys_data):
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body="OK")

    secret_accessor = SecretKeyAccessor(lambda: keys_data)

    write_res = client(encrypt=encrypt, secret_accessor=secret_accessor).write(country=COUNTRY, **record)
    write_res.should.have.key("record")
    assert record.items() <= write_res["record"].items()

    received_record = json.loads(httpretty.last_request().body)

    if encrypt:
        assert received_record.get("version") == keys_data.get("currentVersion")
    else:
        assert received_record.get("version") == SecretKeyAccessor.DEFAULT_VERSION

    for key, value in record.items():
        if isinstance(value, int):
            assert received_record[key] == record[key]
        else:
            assert received_record[key] != record[key]


@httpretty.activate
@pytest.mark.parametrize(
    "record", [get_randomcase_record()],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.parametrize("normalize", [True, False])
@pytest.mark.happy_path
def test_write_normalize_keys_option(client, record, encrypt, normalize):
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body="OK")

    client(encrypt, options={"normalize_keys": normalize}).write(country=COUNTRY, **record)
    received_record = json.loads(httpretty.last_request().body)

    for key, value in record.items():
        if key in ["body", "precommit_body"] or isinstance(value, int):
            continue
        if normalize:
            assert received_record[key] != get_key_hash(record[key])
            assert received_record[key] == get_key_hash(record[key].lower())
        else:
            assert received_record[key] == get_key_hash(record[key])


@httpretty.activate
@pytest.mark.parametrize("records", [TEST_RECORDS])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_batch_write(client, records, encrypt):
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body="OK")

    batch_res = client(encrypt).batch_write(country=COUNTRY, records=records)
    batch_res.should.have.key("records")
    batch_res["records"].should.be.equal(RecordListForBatch(records=records).records)

    received_records = json.loads(httpretty.last_request().body)
    received_records.should.have.key("records")

    for received_record in received_records["records"]:
        original_record = next(
            (item for item in records if (get_key_hash(item.get("record_key")) == received_record.get("record_key"))),
            None,
        )

        for key, value in original_record.items():
            if isinstance(value, int):
                assert received_record[key] == original_record[key]
            else:
                assert received_record[key] != original_record[key]


@httpretty.activate
@pytest.mark.parametrize(
    "records", [get_test_records(use_last_field_value=True, last_field_value=None)[1:]],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_batch_write_with_nones(client, records, encrypt):
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body="OK")

    batch_res = client(encrypt).batch_write(country=COUNTRY, records=records)
    batch_res.should.have.key("records")
    batch_res["records"].should.be.equal(RecordListForBatch(records=records).records)

    received_records = json.loads(httpretty.last_request().body)
    received_records.should.have.key("records")

    for received_record in received_records["records"]:
        original_record = next(
            (item for item in records if (get_key_hash(item.get("record_key")) == received_record.get("record_key"))),
            None,
        )

        for key, value in original_record.items():
            if value is None and key != "body":
                assert key not in received_record
            elif isinstance(value, int):
                assert received_record[key] == original_record[key]
            else:
                assert received_record[key] != original_record[key]


@httpretty.activate
@pytest.mark.parametrize(
    "records", [[get_randomcase_record(), get_randomcase_record()]],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.parametrize("normalize", [True, False])
@pytest.mark.happy_path
def test_batch_write_normalize_keys_option(client, records, encrypt, normalize):
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body="OK")
    client(encrypt, options={"normalize_keys": normalize}).batch_write(country=COUNTRY, records=records)

    received_records = json.loads(httpretty.last_request().body)
    received_records.should.have.key("records")

    for received_record in received_records["records"]:
        original_record = next(
            (
                item
                for item in records
                if (
                    get_key_hash(item.get("record_key").lower() if normalize else item.get("record_key"))
                    == received_record.get("record_key")
                )
            ),
            None,
        )

        for key, value in original_record.items():
            if key in ["body", "precommit_body"] or isinstance(value, int):
                continue
            if normalize:
                assert received_record[key] != get_key_hash(original_record[key])
                assert received_record[key] == get_key_hash(original_record[key].lower())
            else:
                assert received_record[key] == get_key_hash(original_record[key])


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_read(client, record, encrypt):
    stored_record = client(encrypt).encrypt_record(dict(record))

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["record_key"],
        body=json.dumps(stored_record, default=json_converter),
    )

    read_response = client(encrypt).read(country=COUNTRY, record_key=record["record_key"])
    read_response.should.have.key("record")

    for key, value in record.items():
        assert read_response["record"][key] == record[key]


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS[-1:])
@pytest.mark.parametrize("created_at, updated_at", [[get_random_datetime(), get_random_datetime()]])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_read_with_dates(client, record, created_at, updated_at, encrypt):
    stored_record = client(encrypt).encrypt_record(dict(record))

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["record_key"],
        body=json.dumps({**stored_record, "created_at": created_at, "updated_at": updated_at}, default=json_converter),
    )

    read_response = client(encrypt).read(country=COUNTRY, record_key=record["record_key"])
    read_response.should.have.key("record")

    for key, value in record.items():
        assert read_response["record"][key] == record[key]

    assert read_response["record"]["created_at"] == created_at
    assert read_response["record"]["updated_at"] == updated_at


@httpretty.activate
@pytest.mark.parametrize(
    "record_1", [get_test_records()[-1]],
)
@pytest.mark.parametrize(
    "record_2", [get_test_records()[-1]],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.parametrize("keys_data_old", [{"currentVersion": 1, "secrets": [{"secret": SECRET_KEY, "version": 1}]}])
@pytest.mark.parametrize(
    "keys_data_new",
    [
        {
            "currentVersion": 2,
            "secrets": [{"secret": SECRET_KEY, "version": 1}, {"secret": SECRET_KEY + "2", "version": 2}],
        }
    ],
)
@pytest.mark.happy_path
def test_read_multiple_keys(client, record_1, record_2, encrypt, keys_data_old, keys_data_new):
    secret_accessor_old = SecretKeyAccessor(lambda: keys_data_old)
    secret_accessor_new = SecretKeyAccessor(lambda: keys_data_new)

    client_old = client(encrypt=encrypt, secret_accessor=secret_accessor_old)
    client_new = client(encrypt=encrypt, secret_accessor=secret_accessor_new)

    stored_record_1 = client_old.encrypt_record(dict(record_1))
    stored_record_2 = client_new.encrypt_record(dict(record_2))

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record_1["record_key"],
        body=json.dumps(stored_record_1, default=json_converter),
    )

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record_2["record_key"],
        body=json.dumps(stored_record_2, default=json_converter),
    )

    record_1_response = client_new.read(country=COUNTRY, record_key=record_1["record_key"])
    record_2_response = client_new.read(country=COUNTRY, record_key=record_2["record_key"])

    if encrypt:
        assert record_1_response["record"]["version"] == keys_data_old.get("currentVersion")
        assert record_2_response["record"]["version"] == keys_data_new.get("currentVersion")
    else:
        assert record_1_response["record"]["version"] == SecretKeyAccessor.DEFAULT_VERSION
        assert record_2_response["record"]["version"] == SecretKeyAccessor.DEFAULT_VERSION

    omit(record_1_response["record"], "version", "is_encrypted").should.be.equal(record_1)
    omit(record_2_response["record"], "version", "is_encrypted").should.be.equal(record_2)


@httpretty.activate
@pytest.mark.parametrize(
    "record", [get_randomcase_record()],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.parametrize("normalize", [True, False])
@pytest.mark.happy_path
def test_read_normalize_keys_option(client, record, encrypt, normalize):
    stored_record = client(encrypt, options={"normalize_keys": normalize}).encrypt_record(dict(record))
    record_key_hash = get_key_hash(record["record_key"])
    if normalize:
        record_key_hash = get_key_hash(record["record_key"].lower())

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps(stored_record, default=json_converter),
    )

    read_response = client(encrypt, options={"normalize_keys": normalize}).read(
        country=COUNTRY, record_key=record["record_key"]
    )
    read_response.should.have.key("record")

    for key, value in record.items():
        assert record[key] == read_response["record"][key]


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_delete(client, record, encrypt):
    response = {}

    stored_record = dict(record)
    stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.DELETE,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["record_key"],
        body=json.dumps(response, default=json_converter),
    )

    delete_res = client(encrypt).delete(country=COUNTRY, record_key=record["record_key"])
    delete_res.should.be.equal({"success": True})


@httpretty.activate
@pytest.mark.parametrize("record_key", "aAbB")
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.parametrize("normalize", [True, False])
@pytest.mark.happy_path
def test_delete_normalize_keys_option(client, record_key, encrypt, normalize):
    response = {}

    key_hash = get_key_hash(record_key)
    if normalize:
        key_hash = get_key_hash(record_key.lower())

    httpretty.register_uri(
        httpretty.DELETE,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + key_hash,
        body=json.dumps(response, default=json_converter),
    )

    delete_res = client(encrypt, options={"normalize_keys": normalize}).delete(country=COUNTRY, record_key=record_key)
    delete_res.should.be.equal({"success": True})


@httpretty.activate
@pytest.mark.parametrize(
    "query", get_valid_find_filter_test_options(),
)
@pytest.mark.parametrize(
    "records", [TEST_RECORDS[-2:]],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_find(client, query, records, encrypt):
    records = [
        {**record, "updated_at": get_random_datetime(), "created_at": get_random_datetime()} for record in records
    ]
    enc_data = [client(encrypt).encrypt_record(dict(x)) for x in records]

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(len(enc_data), enc_data), default=json_converter),
    )

    find_response = client(encrypt).find(country=COUNTRY, **query)

    received_record = json.loads(httpretty.last_request().body)
    received_record.should.be.a(dict)
    received_record.should.have.key("filter")
    received_record.should.have.key("options")
    received_record["options"].should.equal(
        {"limit": query.get("limit", FindFilter.getFindLimit()), "offset": query.get("offset", 0)}
    )
    received_record["filter"].keys().should.equal(query.keys())

    find_response.should.be.a(dict)

    for data_record in find_response.get("records"):
        match = next(r for r in records if data_record["record_key"] == r["record_key"])
        for key, value in match.items():
            assert data_record[key] == match[key]


@httpretty.activate
@pytest.mark.parametrize(
    "query", [{"key1": "key1"}],
)
@pytest.mark.parametrize(
    "records", [TEST_RECORDS[-2:]],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_find_filters_improper_or_none_keys(client, query, records, encrypt):
    enc_data = [client(encrypt).encrypt_record(dict(x)) for x in records]
    incorrect_random_key = get_random_str()
    incorrect_key = "key11"
    none_key = "key2"
    query[incorrect_random_key] = get_random_str()
    query[incorrect_key] = get_random_str()
    query[none_key] = None

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(len(enc_data), enc_data), default=json_converter),
    )

    client(encrypt).find(country=COUNTRY, **query)

    received_record = json.loads(httpretty.last_request().body)
    received_record.should.be.a(dict)
    received_record.should.have.key("filter")
    received_record["filter"].should_not.have.key(incorrect_key)
    received_record["filter"].should_not.have.key(incorrect_random_key)
    received_record["filter"].should_not.have.key(none_key)
    received_record.should.have.key("options")
    received_record["options"].should.equal(
        {"limit": query.get("limit", FindFilter.getFindLimit()), "offset": query.get("offset", 0)}
    )


@httpretty.activate
@pytest.mark.parametrize(
    "query,records", [({"record_key": "key1"}, TEST_RECORDS[-2:])],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_find_enc_and_non_enc(client, query, records, encrypt):
    records_to_enc = records[len(records) // 2 :]
    records_to_not_enc = records[: len(records) // 2]
    stored_enc_data = [client(encrypt=True).encrypt_record(dict(x)) for x in records_to_enc]
    stored_non_enc_data = [client(encrypt=False).encrypt_record(dict(x)) for x in records_to_not_enc]
    stored_data = stored_enc_data + stored_non_enc_data

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(len(stored_data), stored_data), default=json_converter),
    )

    find_response = client(encrypt).find(country=COUNTRY, **query)

    encrypted_records_received = []
    for data_record in find_response.get("records"):
        match = next((r for r in records if data_record["record_key"] == r["record_key"]), None)
        if match:
            for key, value in match.items():
                assert data_record[key] == match[key]
        else:
            encrypted_records_received.append(data_record)

    assert len(encrypted_records_received) == 0
    if encrypt:
        assert len(find_response.get("records")) == len(records)
        assert find_response.get("errors", None) is None
    else:
        assert len(find_response.get("records")) == len(records_to_not_enc)
        assert len(find_response.get("errors")) == len(records_to_enc)


@httpretty.activate
@pytest.mark.parametrize(
    "query,records", [({"record_key": "key1"}, TEST_RECORDS)],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_find_incorrect_records(client, query, records, encrypt):
    incorrect_records = [
        {"record_key": str(uuid.uuid1()), "body": "2:Something weird here", "version": 0} for i in range(4)
    ]
    enc_data = [client(encrypt).encrypt_record(dict(x)) for x in records]
    stored_data = enc_data + incorrect_records

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(len(stored_data), stored_data), default=json_converter),
    )

    find_response = client(encrypt).find(country=COUNTRY, **query)

    find_response["meta"]["total"].should.equal(len(stored_data))
    find_response.should.have.key("records")
    find_response["records"].should.be.a(list)

    len(find_response["records"]).should.equal(len(enc_data))
    find_response.should.have.key("errors")
    find_response["errors"].should.be.a(list)
    len(find_response["errors"]).should.equal(len(incorrect_records))
    for rec in find_response["errors"]:
        rec.should.have.key("rawData")
        rec.should.have.key("error")


@httpretty.activate
@pytest.mark.parametrize(
    "query", [get_randomcase_record(), get_randomcase_record(use_list_values=True)],
)
@pytest.mark.parametrize(
    "records", [TEST_RECORDS[-2:]],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.parametrize("normalize", [True, False])
@pytest.mark.happy_path
def test_find_normalize_keys_option(client, query, records, encrypt, normalize):
    enc_data = [client(encrypt, options={"normalize_keys": normalize}).encrypt_record(dict(x)) for x in records]

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(len(enc_data), enc_data), default=json_converter),
    )

    client(encrypt, options={"normalize_keys": normalize}).find(country=COUNTRY, **query)

    received_data = json.loads(httpretty.last_request().body)
    received_data.should.be.a(dict)
    received_data.should.have.key("filter")

    for key, value in query.items():
        if isinstance(received_data["filter"][key], list):
            for i, val in enumerate(received_data["filter"][key]):
                if isinstance(val, int):
                    continue
                if normalize:
                    assert val == get_key_hash(value[i].lower())
                else:
                    assert val == get_key_hash(value[i])
        else:
            if isinstance(value, int):
                continue
            if normalize:
                assert received_data["filter"][key] == get_key_hash(value.lower())
            else:
                assert received_data["filter"][key] == get_key_hash(value)


@httpretty.activate
@pytest.mark.parametrize(
    "query,record",
    [
        ({"record_key": "key1"}, {**TEST_RECORDS[-1], "version": 0}),
        ({"record_key": "key2"}, {**TEST_RECORDS[-1], "version": 0}),
        ({"record_key": "key3"}, None),
    ],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_find_one(client, query, record, encrypt):
    stored_record = None
    if record:
        stored_record = dict(record)
        stored_record = client(encrypt).encrypt_record(stored_record)

    count = 0 if stored_record is None else 1
    data = [] if stored_record is None else [stored_record]

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(count, data), default=json_converter),
    )

    find_one_response = client(encrypt).find_one(country=COUNTRY, **query)
    if record:
        find_one_response.should.have.key("record")
        for key, value in record.items():
            assert record[key] == find_one_response["record"][key]
    else:
        find_one_response.should.equal(record)


@httpretty.activate
@pytest.mark.parametrize("records", [TEST_RECORDS[-5:]])
@pytest.mark.parametrize("keys_data_old", [{"currentVersion": 1, "secrets": [{"secret": SECRET_KEY, "version": 1}]}])
@pytest.mark.parametrize(
    "keys_data_new",
    [
        {
            "currentVersion": 2,
            "secrets": [{"secret": SECRET_KEY, "version": 1}, {"secret": SECRET_KEY + "2", "version": 2}],
        }
    ],
)
@pytest.mark.happy_path
def test_migrate(client, records, keys_data_old, keys_data_new):
    secret_accessor_old = SecretKeyAccessor(lambda: keys_data_old)
    secret_accessor_new = SecretKeyAccessor(lambda: keys_data_new)

    stored_records = [
        client(encrypt=True, secret_accessor=secret_accessor_old).encrypt_record(dict(x)) for x in records
    ]

    total_stored = len(stored_records) + 1

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(
            get_default_find_response(len(stored_records), stored_records, total_stored), default=json_converter
        ),
    )

    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body="OK")

    migrate_res = client(encrypt=True, secret_accessor=secret_accessor_new).migrate(country=COUNTRY)

    assert migrate_res["total_left"] == total_stored - len(stored_records)
    assert migrate_res["migrated"] == len(stored_records)

    received_records = json.loads(httpretty.last_request().body)
    for received_record in received_records["records"]:
        original_stored_record = next(
            (item for item in stored_records if item.get("record_key") == received_record.get("record_key")), None
        )

        assert original_stored_record is not None

        assert original_stored_record.get("version") != received_record.get("version")
        assert received_record.get("version") == keys_data_new.get("currentVersion")

        for key, value in original_stored_record.items():
            if key in ["body", "precommit_body", "version"]:
                continue
            assert received_record[key] == original_stored_record[key]

        if original_stored_record.get("body", None):
            assert received_record["body"] != original_stored_record["body"]

        if original_stored_record.get("precommit_body", None):
            assert received_record["precommit_body"] != original_stored_record["precommit_body"]


@httpretty.activate
@pytest.mark.parametrize("records", [get_test_records(use_last_field_value=True)[-5:]])
@pytest.mark.parametrize("keys_data_old", [{"currentVersion": 1, "secrets": [{"secret": SECRET_KEY, "version": 1}]}])
@pytest.mark.parametrize(
    "keys_data_new",
    [
        {
            "currentVersion": 2,
            "secrets": [{"secret": SECRET_KEY, "version": 1}, {"secret": SECRET_KEY + "2", "version": 2}],
        }
    ],
)
@pytest.mark.happy_path
def test_migrate_with_nones(client, records, keys_data_old, keys_data_new):
    secret_accessor_old = SecretKeyAccessor(lambda: keys_data_old)
    secret_accessor_new = SecretKeyAccessor(lambda: keys_data_new)

    stored_records = []
    for record in records:
        stored_record = client(encrypt=True, secret_accessor=secret_accessor_old).encrypt_record(dict(record))
        for k in record:
            if k != "body" and record.get(k, None) is None:
                stored_record[k] = None
        stored_records.append(stored_record)

    total_stored = len(stored_records) + 1

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(
            get_default_find_response(len(stored_records), stored_records, total_stored), default=json_converter
        ),
    )

    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body="OK")

    client(encrypt=True, secret_accessor=secret_accessor_new).migrate(country=COUNTRY)

    received_records = json.loads(httpretty.last_request().body)
    for received_record in received_records["records"]:
        original_stored_record = next(
            (item for item in stored_records if item.get("record_key") == received_record.get("record_key")), None
        )

        for key, value in original_stored_record.items():
            if value is None:
                assert key not in received_record
                continue
            if key in ["body", "precommit_body", "version"]:
                continue
            assert received_record[key] == original_stored_record[key]

        if original_stored_record.get("body", None):
            assert received_record["body"] != original_stored_record["body"]

        if original_stored_record.get("precommit_body", None):
            assert received_record["precommit_body"] != original_stored_record["precommit_body"]


@httpretty.activate
@pytest.mark.parametrize(
    "record,country,countries",
    [
        ({"record_key": "key1", "version": 0}, "ru", [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]),
        ({"record_key": "key1", "version": 0}, "ag", [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]),
    ],
)
@pytest.mark.happy_path
def test_default_endpoints(client, record, country, countries):
    stored_record = client().encrypt_record(dict(record))

    midpop_ids = [c["id"].lower() for c in countries if c["direct"]]
    is_midpop = country in midpop_ids
    endpoint = HttpClient.get_pop_url(country) if is_midpop else HttpClient.get_pop_url(HttpClient.DEFAULT_COUNTRY)

    countries_url = HttpClient.DEFAULT_COUNTRIES_ENDPOINT
    httpretty.register_uri(
        httpretty.GET, countries_url, body=json.dumps({"countries": countries}, default=json_converter)
    )

    read_url = endpoint + "/v2/storage/records/" + country + "/" + stored_record["record_key"]
    httpretty.register_uri(httpretty.GET, read_url, body=json.dumps(record, default=json_converter))

    client(endpoint=None).read(country=country, record_key=record["record_key"])

    latest_request = httpretty.HTTPretty.latest_requests[-1]
    prev_request = httpretty.HTTPretty.latest_requests[-2]

    latest_request_url = "https://" + latest_request.headers.get("Host", "") + latest_request.path
    prev_request_url = "https://" + prev_request.headers.get("Host", "") + prev_request.path

    assert latest_request_url == read_url
    assert prev_request_url == countries_url


@httpretty.activate
@pytest.mark.parametrize(
    "record,country,countries",
    [
        ({"record_key": "key1", "version": 0}, "ru", [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]),
        ({"record_key": "key1", "version": 0}, "ag", [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]),
    ],
)
@pytest.mark.happy_path
def test_custom_countries_endpoint(client, record, country, countries):
    stored_record = client().encrypt_record(dict(record))

    midpop_ids = [c["id"].lower() for c in countries if c["direct"]]
    is_midpop = country in midpop_ids
    endpoint = HttpClient.get_pop_url(country) if is_midpop else HttpClient.get_pop_url(HttpClient.DEFAULT_COUNTRY)

    countries_url = "https://countries.com/"
    httpretty.register_uri(
        httpretty.GET, countries_url, body=json.dumps({"countries": countries}, default=json_converter)
    )

    read_url = endpoint + "/v2/storage/records/" + country + "/" + stored_record["record_key"]

    httpretty.register_uri(httpretty.GET, read_url, body=json.dumps(record, default=json_converter))

    client(endpoint=None, options={"countries_endpoint": countries_url}).read(
        country=country, record_key=record["record_key"]
    )

    latest_request = httpretty.HTTPretty.latest_requests[-1]
    prev_request = httpretty.HTTPretty.latest_requests[-2]

    latest_request_url = "https://" + latest_request.headers.get("Host", "") + latest_request.path
    prev_request_url = "https://" + prev_request.headers.get("Host", "") + prev_request.path

    assert latest_request_url == read_url
    assert prev_request_url == countries_url


@httpretty.activate
@pytest.mark.parametrize(
    "record,country,countries",
    [({"record_key": "key1", "version": 0}, "ru", [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}])],
)
@pytest.mark.error_path
def test_custom_countries_endpoint_failure(client, record, country, countries):
    countries_url = "https://countries.com/"
    httpretty.register_uri(httpretty.GET, countries_url, body="error", status=500)

    client(endpoint=None, options={"countries_endpoint": countries_url}).read.when.called_with(
        country=country, record_key=record["record_key"]
    ).should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.parametrize("record,country", [({"record_key": "key1"}, "ru"), ({"record_key": "key1"}, "ag")])
@pytest.mark.happy_path
def test_custom_endpoint(client, record, country):
    stored_record = client().encrypt_record(dict(record))
    read_url = POPAPI_URL + "/v2/storage/records/" + country + "/" + stored_record["record_key"]
    httpretty.register_uri(httpretty.GET, read_url, body=json.dumps(stored_record, default=json_converter))

    client(endpoint=POPAPI_URL).read(country=country, record_key=record["record_key"])

    latest_request = httpretty.HTTPretty.last_request
    latest_request_url = "https://" + latest_request.headers.get("Host", "") + latest_request.path

    assert latest_request_url == read_url


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize(
    "custom_encryption",
    [
        [
            {
                "encrypt": lambda input, key, key_version: Fernet(key).encrypt(input.encode("utf8")).decode("utf8"),
                "decrypt": lambda input, key, key_version: Fernet(key).decrypt(input.encode("utf8")).decode("utf8"),
                "version": "test",
                "isCurrent": True,
            }
        ],
    ],
)
@pytest.mark.happy_path
def test_custom_encryption_write(client, record, custom_encryption):
    key = InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH))
    secret_key_accessor = SecretKeyAccessor(
        lambda: {"currentVersion": 1, "secrets": [{"secret": key, "version": 1, "isForCustomEncryption": True}]}
    )

    client = client(secret_accessor=secret_key_accessor, custom_encryption=custom_encryption)

    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body="OK")

    client.write(country=COUNTRY, **record)

    received_record = json.loads(httpretty.last_request().body)

    for key, value in record.items():
        if isinstance(value, int):
            assert received_record[key] == record[key]
        else:
            assert received_record[key] != record[key]


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize(
    "custom_encryption",
    [
        [
            {
                "encrypt": lambda input, key, key_version: Fernet(key).encrypt(input.encode("utf8")).decode("utf8"),
                "decrypt": lambda input, key, key_version: Fernet(key).decrypt(input.encode("utf8")).decode("utf8"),
                "version": "test",
                "isCurrent": True,
            }
        ],
    ],
)
@pytest.mark.happy_path
def test_custom_encryption_read(client, record, custom_encryption):
    key = InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH))
    secret_key_accessor = SecretKeyAccessor(
        lambda: {"currentVersion": 1, "secrets": [{"secret": key, "version": 1, "isForCustomEncryption": True}]}
    )

    country = "us"

    client = client(secret_accessor=secret_key_accessor, custom_encryption=custom_encryption)

    stored_record = client.encrypt_record(dict(record))
    read_record_url = POPAPI_URL + "/v2/storage/records/" + country + "/" + stored_record["record_key"]
    httpretty.register_uri(httpretty.GET, read_record_url, body=json.dumps(stored_record, default=json_converter))

    res = client.read(country=country, record_key=record["record_key"])

    for key, value in record.items():
        assert record[key] == res["record"][key]


@httpretty.activate
@pytest.mark.parametrize(
    "custom_encryption",
    [
        [
            {
                "encrypt": lambda input, key, key_version: Fernet(key).encrypt(input.encode("utf8")).decode("utf8"),
                "decrypt": lambda input, key, key_version: Fernet(key).decrypt(input.encode("utf8")).decode("utf8"),
                "version": "test",
                "isCurrent": True,
            }
        ],
    ],
)
@pytest.mark.happy_path
def test_primary_custom_encryption_with_default_encryption(client, custom_encryption):
    record1 = {"record_key": str(uuid.uuid1()), "body": "body1"}
    record2 = {"record_key": str(uuid.uuid1()), "body": "body2"}

    key = InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH))
    secret_key_accessor_old = SecretKeyAccessor(
        lambda: {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1}]}
    )
    secret_key_accessor_new = SecretKeyAccessor(
        lambda: {
            "currentVersion": 2,
            "secrets": [
                {"secret": "password", "version": 1},
                {"secret": key, "version": 2, "isForCustomEncryption": True},
            ],
        }
    )

    client_old = client(secret_accessor=secret_key_accessor_old)
    client_new = client(secret_accessor=secret_key_accessor_new, custom_encryption=custom_encryption)

    stored_record1 = client_old.encrypt_record(dict(record1))
    read_record1_url = POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record1["record_key"]
    httpretty.register_uri(httpretty.GET, read_record1_url, body=json.dumps(stored_record1, default=json_converter))

    stored_record2 = client_new.encrypt_record(dict(record2))
    read_record2_url = POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record2["record_key"]
    httpretty.register_uri(httpretty.GET, read_record2_url, body=json.dumps(stored_record2, default=json_converter))

    rec1_res = client_new.read(country=COUNTRY, record_key=record1["record_key"])
    rec2_res = client_new.read(country=COUNTRY, record_key=record2["record_key"])

    omit(rec1_res["record"], "version", "is_encrypted").should.be.equal(record1)
    omit(rec2_res["record"], "version", "is_encrypted").should.be.equal(record2)


@httpretty.activate
@pytest.mark.parametrize(
    "custom_encryption",
    [
        [
            {
                "encrypt": lambda input, key, key_version: Fernet(key).encrypt(input.encode("utf8")).decode("utf8"),
                "decrypt": lambda input, key, key_version: Fernet(key).decrypt(input.encode("utf8")).decode("utf8"),
                "version": "test",
            }
        ],
    ],
)
@pytest.mark.happy_path
def test_custom_encryption_with_primary_default_encryption(client, custom_encryption):
    record1 = {"record_key": str(uuid.uuid1()), "body": "body1"}
    record2 = {"record_key": str(uuid.uuid1()), "body": "body2"}

    key = InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH))
    secret_key_accessor_old = SecretKeyAccessor(
        lambda: {"currentVersion": 1, "secrets": [{"secret": key, "version": 1, "isForCustomEncryption": True}]}
    )
    secret_key_accessor_new = SecretKeyAccessor(
        lambda: {
            "currentVersion": 2,
            "secrets": [
                {"secret": key, "version": 1, "isForCustomEncryption": True},
                {"secret": "password", "version": 2},
            ],
        }
    )

    custom_encryption_old = [{**custom_encryption[0], "isCurrent": True}]
    client_old = client(secret_accessor=secret_key_accessor_old, custom_encryption=custom_encryption_old)
    client_new = client(secret_accessor=secret_key_accessor_new, custom_encryption=custom_encryption)

    stored_record1 = client_old.encrypt_record(dict(record1))
    read_record1_url = POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record1["record_key"]
    httpretty.register_uri(httpretty.GET, read_record1_url, body=json.dumps(stored_record1, default=json_converter))

    stored_record2 = client_new.encrypt_record(dict(record2))
    read_record2_url = POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record2["record_key"]
    httpretty.register_uri(httpretty.GET, read_record2_url, body=json.dumps(stored_record2, default=json_converter))

    rec1_res = client_new.read(country=COUNTRY, record_key=record1["record_key"])
    rec2_res = client_new.read(country=COUNTRY, record_key=record2["record_key"])

    assert rec1_res["record"]["record_key"] == record1["record_key"]
    assert rec2_res["record"]["record_key"] == record2["record_key"]


@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.happy_path
def test_enc_payload_for_different_envs(client, record):
    client_1 = client(environment_id="test1")
    client_2 = client(environment_id="test2")

    record_via_client_1 = client_1.encrypt_record(record)
    record_via_client_2 = client_2.encrypt_record(record)

    for key, value in record.items():
        if not isinstance(value, (int, datetime)):
            assert record_via_client_1[key] != record_via_client_2[key]


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize(
    "custom_encryption",
    [
        [
            {
                "encrypt": lambda input, key, key_version: Fernet(key).encrypt(input.encode("utf8")).decode("utf8"),
                "decrypt": lambda input, key, key_version: Fernet(key).decrypt(input.encode("utf8")).decode("utf8"),
                "version": "test",
                "isCurrent": True,
            }
        ],
    ],
)
@pytest.mark.error_path
def test_custom_encryption_without_proper_keys(client, record, custom_encryption):
    key = InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH))
    secret_key_accessor = SecretKeyAccessor(
        lambda: {"currentVersion": 1, "secrets": [{"secret": key, "version": 1, "isKey": True}]}
    )

    client.when.called_with(secret_accessor=secret_key_accessor, custom_encryption=custom_encryption).should.throw(
        StorageClientException
    )


@httpretty.activate
@pytest.mark.parametrize("record", [TEST_RECORDS[0]])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.error_path
def test_read_not_found(client, record, encrypt):
    stored_record = dict(record)
    stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.GET, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["record_key"], status=404,
    )

    client(encrypt).read.when.called_with(country=COUNTRY, record_key=record["record_key"]).should.throw(
        StorageServerException
    )


@httpretty.activate
@pytest.mark.parametrize(
    "query",
    [
        {"record_key": "key1", "limit": 0},
        {"record_key": "key1", "limit": -1},
        {"record_key": "key1", "limit": 101},
        {"record_key": "key1", "limit": 1, "offset": -1},
    ],
)
@pytest.mark.error_path
def test_find_error(client, query):
    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(0, []), default=json_converter),
    )

    client().find.when.called_with(country=COUNTRY, **query).should.have.raised(StorageClientException)


@pytest.mark.parametrize(
    "kwargs",
    [
        ({}),
        ({"api_key": "test"}),
        ({"environment_id": "test"}),
        ({"environment_id": "test", "api_key": "test"}),
        ({"environment_id": "test", "api_key": "test", "encrypt": True}),
    ],
)
@pytest.mark.error_path
def test_init_error_on_insufficient_args(client, kwargs):
    Storage.when.called_with(**kwargs).should.have.raised(Exception)


@httpretty.activate
@pytest.mark.parametrize("record", [{"record_key": str(uuid.uuid1())}])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.error_path
def test_error_on_popapi_error(client, record, encrypt):
    stored_record = client(encrypt).encrypt_record(dict(record))

    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find", status=400)
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, status=400)
    httpretty.register_uri(
        httpretty.GET, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["record_key"], status=400,
    )
    httpretty.register_uri(
        httpretty.DELETE, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["record_key"], status=400,
    )

    client(encrypt).write.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerException)
    client(encrypt).read.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerException)
    client(encrypt).delete.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerException)
    client(encrypt).find.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerException)
    client(encrypt).find_one.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerException)


@pytest.mark.parametrize("record", [{}, {"country": COUNTRY}, {"record_key": "key1"}])
@pytest.mark.error_path
def test_error_write_insufficient_args(client, record):
    client().write.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.parametrize("records", [[], [{}]])
@pytest.mark.error_path
def test_error_batch_write_invalid_records(client, records):
    client().batch_write.when.called_with(country=COUNTRY, records=records).should.have.raised(StorageClientException)


@pytest.mark.parametrize("record", [{"country": None, "key": None}])
@pytest.mark.error_path
def test_error_read_insufficient_args(client, record):
    client().read.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.parametrize("record", [{}, {"country": COUNTRY}, {"key": "key1"}])
@pytest.mark.error_path
def test_error_delete_insufficient_args(client, record):
    client().delete.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.parametrize("record", [{}])
@pytest.mark.error_path
def test_error_find_insufficient_args(client, record):
    client().find.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.parametrize("record", [{}])
@pytest.mark.error_path
def test_error_find_one_insufficient_args(client, record):
    client().find_one.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.error_path
def test_error_migrate_without_encryption(client):
    client(encrypt=False).migrate.when.called_with(country=COUNTRY).should.have.raised(StorageClientException)


@pytest.mark.error_path
def test_migrate_with_enc_disabled(client):
    client(encrypt=False).migrate.when.called_with("").should.have.raised(
        StorageClientException, "This method is only allowed with encryption enabled"
    )
