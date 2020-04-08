import os
import uuid

import pytest
import sure  # noqa: F401
from pydantic import ValidationError


from incountry.models import (
    Country,
    CustomEncryptionOptions,
    FindFilter,
    HttpOptions,
    Record,
    RecordFromServer,
    RecordListForBatch,
    SecretsData,
    StorageWithEnv,
)
from incountry import SecretKeyAccessor

TEST_RECORDS = [
    {"key": str(uuid.uuid1())},
    {"key": str(uuid.uuid1()), "body": "test"},
    {"key": str(uuid.uuid1()), "body": "test", "key2": "key2"},
    {"key": str(uuid.uuid1()), "body": "test", "key2": "key2", "key3": "key3"},
    {"key": str(uuid.uuid1()), "body": "test", "key2": "key2", "key3": "key3", "profile_key": "profile_key"},
    {
        "key": str(uuid.uuid1()),
        "body": "test",
        "key2": "key2",
        "key3": "key3",
        "profile_key": "profile_key",
        "range_key": 1,
    },
]

INVALID_RECORDS = [
    {"key": ""},
    {"key": 1},
    {"key": "key", "body": 1},
    {"key": "key", "version": -1},
    {"key": "key", "body": "body", "key2": 1},
    {"key": "key", "body": "test", "key2": "key2", "key3": 1},
    {"key": "key", "body": "test", "key2": "key2", "key3": "key3", "profile_key": 1},
    {
        "key": "key",
        "body": "test",
        "key2": "key2",
        "key3": "key3",
        "profile_key": "profile_key",
        "range_key": "range_key",
    },
    {
        "key": "key",
        "body": "test",
        "key2": "key2",
        "key3": "key3",
        "profile_key": "profile_key",
        "range_key": 1,
        "version": "version",
    },
]
INVALID_RECORDS_FOR_BATCH = [
    [],
    {},
    (),
    True,
    False,
    0,
    1,
    "",
    "record",
    *INVALID_RECORDS,
]


@pytest.fixture(autouse=True)
def clear_envs():
    if "INC_API_KEY" in os.environ:
        del os.environ["INC_API_KEY"]
    if "INC_ENVIRONMENT_ID" in os.environ:
        del os.environ["INC_ENVIRONMENT_ID"]
    if "INC_ENDPOINT" in os.environ:
        del os.environ["INC_ENDPOINT"]
    yield
    if "INC_API_KEY" in os.environ:
        del os.environ["INC_API_KEY"]
    if "INC_ENVIRONMENT_ID" in os.environ:
        del os.environ["INC_ENVIRONMENT_ID"]
    if "INC_ENDPOINT" in os.environ:
        del os.environ["INC_ENDPOINT"]


@pytest.mark.parametrize(
    "country", ["us", "US", "uS", "Us"],
)
@pytest.mark.happy_path
def test_valid_country(country):
    item = Country(country=country)

    assert country.lower() == item.country


@pytest.mark.parametrize(
    "country", ["usa", 0, 1, True, False, "", "u", [], {}, ()],
)
@pytest.mark.error_path
def test_invalid_country(country):
    Country.when.called_with(country=country).should.throw(ValidationError)


@pytest.mark.parametrize(
    "configs",
    [
        [
            {
                "encrypt": lambda input, key, key_version: "text",
                "decrypt": lambda input, key, key_version: "text",
                "version": "1",
                "isCurrent": True,
            }
        ]
    ],
)
@pytest.mark.happy_path
def test_valid_custom_enc_configs(configs):
    CustomEncryptionOptions.when.called_with(configs=configs).should_not.throw(Exception)


@pytest.mark.parametrize(
    "configs, error_text",
    [
        ([{"encrypt": True, "decrypt": lambda text: "text", "version": "1", "isCurrent": True}], "is not callable"),
        ([{"encrypt": lambda text: "text", "decrypt": True, "version": "1", "isCurrent": True}], "is not callable"),
        (
            [{"encrypt": lambda text: "text", "decrypt": lambda text: "text", "version": 1, "isCurrent": True}],
            "str type expected",
        ),
        (
            [{"encrypt": lambda text: "text", "decrypt": lambda text: "text", "version": "1", "isCurrent": 1}],
            "value is not a valid boolean",
        ),
        (
            [
                {
                    "encrypt": lambda input, key, key_version: "text",
                    "decrypt": lambda input, key, key_version: "text",
                    "version": "1",
                    "isCurrent": True,
                },
                {
                    "encrypt": lambda input, key, key_version: "text",
                    "decrypt": lambda input, key, key_version: "text",
                    "version": "2",
                    "isCurrent": True,
                },
            ],
            "There must be at most one current version of custom encryption",
        ),
        (
            [
                {
                    "encrypt": lambda input, key, key_version: "text",
                    "decrypt": lambda input, key, key_version: "text",
                    "version": "1",
                    "isCurrent": True,
                },
                {
                    "encrypt": lambda input, key, key_version: "text",
                    "decrypt": lambda input, key, key_version: "text",
                    "version": "1",
                },
            ],
            "Versions must be unique",
        ),
    ],
)
@pytest.mark.happy_path
def test_invalid_custom_enc_configs(configs, error_text):
    CustomEncryptionOptions.when.called_with(configs=configs).should.throw(ValidationError, error_text)


@pytest.mark.happy_path
def test_default_find_filter():
    item = FindFilter()

    assert item.limit == FindFilter.getFindLimit()
    assert item.offset == 0


@pytest.mark.parametrize(
    "filter", [{"limit": 20, "offset": 20}],
)
@pytest.mark.happy_path
def test_valid_limit_offset_find_filter(filter):
    item = FindFilter(limit=filter["limit"], offset=filter["offset"])

    assert item.limit == filter["limit"]
    assert item.offset == filter["offset"]


@pytest.mark.parametrize("filter_key", ["key", "key2", "key3", "profile_key"])
@pytest.mark.parametrize(
    "filter",
    [
        "single_value",
        ["list_value_1", "list_value_2", "list_value_3"],
        {"$not": "not_single_value"},
        {"$not": ["list_not_value_1", "list_not_value_2", "list_not_value_3"]},
    ],
)
@pytest.mark.happy_path
def test_valid_str_filters_find_filter(filter_key, filter):
    kwargs = {}
    kwargs[filter_key] = filter
    item = FindFilter(**kwargs)

    assert getattr(item, filter_key) == filter


@pytest.mark.parametrize("filter_key", ["version", "range_key"])
@pytest.mark.parametrize(
    "filter",
    [
        1,
        [1, 2, 3],
        {"$not": 1},
        {"$not": [1, 2, 3]},
        {"$gt": 1},
        {"$gte": 1},
        {"$lt": 1},
        {"$lte": 1},
        {"$gt": 1, "$lt": 1},
        {"$gte": 1, "$lt": 1},
        {"$gt": 1, "$lte": 1},
        {"$gte": 1, "$lte": 1},
    ],
)
@pytest.mark.happy_path
def test_valid_int_filters_find_filter(filter_key, filter):
    kwargs = {}
    kwargs[filter_key] = filter
    item = FindFilter(**kwargs)

    assert getattr(item, filter_key) == filter


@pytest.mark.parametrize("filter_key", ["key", "key2", "key3", "profile_key"])
@pytest.mark.parametrize("values", [[0, 1, [], {}, (), False, True]])
@pytest.mark.error_path
def test_invalid_str_filters_find_filter(filter_key, values):
    kwargs = {}
    kwargs[filter_key] = values
    FindFilter.when.called_with(**kwargs).should.throw(ValidationError)

    kwargs = {}
    kwargs[filter_key] = {"$not": values}
    FindFilter.when.called_with(**kwargs).should.throw(ValidationError)

    for value in values:
        kwargs = {}
        kwargs[filter_key] = value
        FindFilter.when.called_with(**kwargs).should.throw(ValidationError)

        kwargs = {}
        kwargs[filter_key] = {"$not": value}
        FindFilter.when.called_with(**kwargs).should.throw(ValidationError)


@pytest.mark.parametrize("filter_key", ["version", "range_key"])
@pytest.mark.parametrize("values", [["text", "", [], {}, (), False, True]])
@pytest.mark.parametrize("operator", ["$not", "$gt", "$gte", "$lt", "$lte"])
@pytest.mark.error_path
def test_invalid_int_filters_find_filter(filter_key, values, operator):
    kwargs = {}
    kwargs[filter_key] = values
    FindFilter.when.called_with(**kwargs).should.throw(ValidationError)

    kwargs = {}
    kwargs[filter_key] = {}
    kwargs[filter_key][operator] = values
    FindFilter.when.called_with(**kwargs).should.throw(ValidationError)

    for value in values:
        kwargs = {}
        kwargs[filter_key] = value
        FindFilter.when.called_with(**kwargs).should.throw(ValidationError)

        kwargs = {}
        kwargs[filter_key] = {}
        kwargs[filter_key][operator] = values
        FindFilter.when.called_with(**kwargs).should.throw(ValidationError)


@pytest.mark.parametrize("filter_key", ["key", "key2", "key3", "profile_key", "version", "range_key"])
@pytest.mark.parametrize("operator", ["gt", "gte", "lt", "lte", "not", "$no", "$", "", False, True, 0, 1, ()])
@pytest.mark.error_path
def test_invalid_operators_find_filter(filter_key, operator):
    kwargs = {}
    kwargs[filter_key] = {}
    kwargs[filter_key][operator] = "value"
    FindFilter.when.called_with(**kwargs).should.throw(ValidationError)


@pytest.mark.parametrize("filter_key", ["version", "range_key"])
@pytest.mark.parametrize("operators", [["$gt", "$gte"], ["$lt", "$lte"]])
@pytest.mark.error_path
def test_invalid_int_operators_combinations_find_filter(filter_key, operators):
    kwargs = {}
    kwargs[filter_key] = {}
    for operator in operators:
        kwargs[filter_key][operator] = 1
    FindFilter.when.called_with(**kwargs).should.throw(
        ValidationError, "Must contain not more than one key from the following group"
    )


@pytest.mark.parametrize(
    "http_options", [{}, {"timeout": 1}, {"timeout": 100}],
)
@pytest.mark.error_path
def test_valid_http_options(http_options):
    HttpOptions.when.called_with(**http_options).should_not.throw(ValidationError)


@pytest.mark.parametrize(
    "http_options",
    [
        {"timeout": -1},
        {"timeout": 0},
        {"timeout": []},
        {"timeout": {}},
        {"timeout": ""},
        {"timeout": ()},
        {"timeout": True},
        {"timeout": False},
    ],
)
@pytest.mark.error_path
def test_invalid_http_options(http_options):
    HttpOptions.when.called_with(**http_options).should.throw(ValidationError)


@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.happy_path
def test_valid_record(record):
    item = Record(**record)

    for key in ["key", "body", "key2", "key3", "profile_key", "range_key", "version"]:
        if key in record:
            assert getattr(item, key) == record[key]


@pytest.mark.parametrize("record", INVALID_RECORDS)
@pytest.mark.error_path
def test_invalid_record(record):
    Record.when.called_with(**record).should.throw(ValidationError)


@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.happy_path
def test_valid_record_from_server(record):
    record = {**record, "version": 1}
    item = RecordFromServer(**record)

    for key in ["key", "body", "key2", "key3", "profile_key", "range_key", "version"]:
        if key in record:
            assert getattr(item, key) == record[key]


@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.error_path
def test_invalid_record_from_server(record):
    RecordFromServer.when.called_with(**record).should.throw(ValidationError)


@pytest.mark.happy_path
def test_valid_records_for_batch():
    RecordListForBatch.when.called_with(records=TEST_RECORDS).should_not.throw(ValidationError)


@pytest.mark.parametrize("record", INVALID_RECORDS_FOR_BATCH)
@pytest.mark.error_path
def test_invalid_records_for_batch(record):
    RecordListForBatch.when.called_with(records=[record]).should.throw(ValidationError)


@pytest.mark.error_path
def test_invalid_empty_records_for_batch():
    RecordListForBatch.when.called_with(records=[]).should.throw(ValidationError)


@pytest.mark.parametrize(
    "keys_data",
    [
        {"currentVersion": 1, "secrets": [{"secret": "password1", "version": 1}]},
        {
            "currentVersion": 1,
            "secrets": [
                {"secret": "password1", "version": 1, "isKey": False},
                {"secret": "password2", "version": 2, "isKey": True},
            ],
        },
        {
            "currentVersion": 2,
            "secrets": [{"secret": "password1", "version": 1}, {"secret": "password2", "version": 2}],
        },
        {"currentVersion": 1, "secrets": [{"secret": "password1", "version": 1}]},
        {"currentVersion": 1, "secrets": [{"secret": "password1", "version": 1}]},
    ],
)
@pytest.mark.error_path
def test_valid_secrets_data(keys_data):
    item = SecretsData(**keys_data)

    assert item.currentVersion == keys_data["currentVersion"]
    for i, secret_data in enumerate(keys_data["secrets"]):
        for k in ["secret", "version"]:
            if k in secret_data:
                assert secret_data[k] == item.secrets[i][k]
        if "isKey" in secret_data:
            assert secret_data["isKey"] == item.secrets[i]["isKey"]
        else:
            assert item.secrets[i]["isKey"] is False


@pytest.mark.parametrize(
    "keys_data",
    [
        {"secrets": [{"secret": "password", "version": 1}]},
        {"currentVersion": 1},
        {"currentVersion": "1", "secrets": [{"secret": "password", "version": 1}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": "1"}]},
        {"currentVersion": 1, "secrets": [{"secret": 1, "version": 1}]},
        {"currentVersion": 1, "secrets": []},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": "yes"}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": 1}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 0}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": -1}, {"secret": "password", "version": 1}]},
        {"currentVersion": 0, "secrets": [{"secret": "password", "version": 1}]},
        {"currentVersion": -1, "secrets": [{"secret": "password", "version": -1}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": -1}]},
        {"currentVersion": -1, "secrets": [{"secret": "password", "version": 1}]},
    ],
)
@pytest.mark.error_path
def test_invalid_secrets_data(keys_data):
    SecretsData.when.called_with(**keys_data).should.have.raised(ValidationError)


@pytest.mark.parametrize(
    "keys_data", [{"currentVersion": 2, "secrets": [{"secret": "password", "version": 1}]}],
)
@pytest.mark.error_path
def test_invalid_secrets_data_current_version_not_found(keys_data):
    SecretsData.when.called_with(**keys_data).should.have.raised(
        ValidationError, "non of the secret versions match currentVersion"
    )


@pytest.mark.parametrize(
    "storage_params",
    [
        {"environment_id": "environment_id", "api_key": "api_key", "encrypt": False},
        {
            "environment_id": "environment_id",
            "api_key": "api_key",
            "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
        },
        {
            "environment_id": "environment_id",
            "api_key": "api_key",
            "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
            "endpoint": "http://popapi.com",
        },
        {
            "environment_id": "environment_id",
            "api_key": "api_key",
            "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
            "endpoint": "http://popapi.com",
            "debug": True,
        },
        {
            "environment_id": "environment_id",
            "api_key": "api_key",
            "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
            "endpoint": "http://popapi.com",
            "debug": True,
        },
    ],
)
@pytest.mark.happy_path
def test_valid_storage(storage_params):
    item = StorageWithEnv(**storage_params)

    for param in storage_params:
        if isinstance(storage_params[param], SecretKeyAccessor):
            assert isinstance(getattr(item, param), SecretKeyAccessor)
        else:
            assert getattr(item, param) == storage_params[param]


@pytest.mark.parametrize(
    "options", [{"http_options": {"timeout": 1}}],
)
@pytest.mark.happy_path
def test_valid_options_storage(options):
    StorageWithEnv.when.called_with(
        **{
            "environment_id": "environment_id",
            "api_key": "api_key",
            "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
            "options": options,
        }
    ).should_not.throw(Exception)


@pytest.mark.parametrize(
    "options",
    [
        [],
        {},
        (),
        "",
        -1,
        0,
        1,
        None,
        True,
        False,
        {"http_options": []},
        {"http_options": {}},
        {"http_options": ()},
        {"http_options": ""},
        {"http_options": -1},
        {"http_options": 0},
        {"http_options": 1},
        {"http_options": None},
        {"http_options": True},
        {"http_options": False},
        {"http_options": {"timeout": -1}},
        {"http_options": {"timeout": 0}},
        {"http_options": {"timeout": []}},
        {"http_options": {"timeout": {}}},
        {"http_options": {"timeout": ""}},
        {"http_options": {"timeout": ()}},
        {"http_options": {"timeout": True}},
        {"http_options": {"timeout": False}},
    ],
)
@pytest.mark.happy_path
def test_invalid_options_storage(options):
    StorageWithEnv.when.called_with(
        **{
            "environment_id": "environment_id",
            "api_key": "api_key",
            "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
            "options": options,
        }
    ).should.throw(ValidationError)


@pytest.mark.parametrize(
    "storage_params, env_params",
    [
        (
            {"encrypt": False},
            [
                {"env_var": "INC_API_KEY", "value": "api_key_env_1", "param": "api_key"},
                {"env_var": "INC_ENVIRONMENT_ID", "value": "env_id_env_1", "param": "environment_id"},
            ],
        ),
        (
            {"api_key": "api_key_2", "encrypt": False},
            [{"env_var": "INC_ENVIRONMENT_ID", "value": "env_id_env_2", "param": "environment_id"}],
        ),
        (
            {"environment_id": "env_id_3", "encrypt": False},
            [{"env_var": "INC_API_KEY", "value": "api_key_env_3", "param": "api_key"}],
        ),
        (
            {"environment_id": "environment_id", "api_key": "api_key", "encrypt": False},
            [{"env_var": "INC_ENDPOINT", "value": "http://popapi.com", "param": "endpoint"}],
        ),
    ],
)
@pytest.mark.happy_path
def test_valid_storage_with_env_params(storage_params, env_params):
    for param_data in env_params:
        os.environ[param_data["env_var"]] = param_data["value"]

    item = StorageWithEnv(**storage_params)

    for param in storage_params:
        assert getattr(item, param) == storage_params[param]
    for param_data in env_params:
        assert getattr(item, param_data["param"]) == param_data["value"]


@pytest.mark.parametrize(
    "storage_params, env_params",
    [
        (
            {"encrypt": False},
            [
                {"env_var": "INC_API_KEY", "value": "", "param": "api_key"},
                {"env_var": "INC_ENVIRONMENT_ID", "value": "env_id_env_1", "param": "environment_id"},
            ],
        ),
        (
            {"encrypt": False},
            [
                {"env_var": "INC_API_KEY", "value": "api_key_env_1", "param": "api_key"},
                {"env_var": "INC_ENVIRONMENT_ID", "value": "", "param": "environment_id"},
            ],
        ),
        (
            {"api_key": "api_key_2", "encrypt": False},
            [{"env_var": "INC_ENVIRONMENT_ID", "value": "", "param": "environment_id"}],
        ),
        (
            {"environment_id": "env_id_3", "encrypt": False},
            [{"env_var": "INC_API_KEY", "value": "", "param": "api_key"}],
        ),
        (
            {"environment_id": "environment_id", "api_key": "api_key", "encrypt": False},
            [{"env_var": "INC_ENDPOINT", "value": "not a url", "param": "endpoint"}],
        ),
    ],
)
@pytest.mark.error_path
def test_valid_storage_with_invalid_env_params(storage_params, env_params):
    for param_data in env_params:
        os.environ[param_data["env_var"]] = param_data["value"]

    StorageWithEnv.when.called_with(**storage_params).should.throw(ValidationError)


@pytest.mark.parametrize(
    "storage_params",
    [
        {},
        {"environment_id": "environment_id", "encrypt": False},
        {"api_key": "api_key", "encrypt": False},
        {"environment_id": "environment_id", "api_key": "api_key"},
        {"environment_id": "environment_id", "api_key": "api_key", "encrypt": 1},
        {"environment_id": "environment_id", "api_key": "api_key", "encrypt": 0},
        {"environment_id": "environment_id", "api_key": "api_key", "encrypt": "encrypt"},
        {"environment_id": "environment_id", "api_key": "api_key", "encrypt": False, "debug": 1},
        {"environment_id": "environment_id", "api_key": "api_key", "encrypt": False, "debug": 0},
        {"environment_id": "environment_id", "api_key": "api_key", "encrypt": False, "debug": "info"},
        {"environment_id": "", "api_key": "api_key", "encrypt": False},
        {"environment_id": "environment_id", "api_key": "", "encrypt": False},
        {"environment_id": 1, "api_key": "api_key", "encrypt": False},
        {"environment_id": "environment_id", "api_key": 1, "encrypt": False},
        {"environment_id": 0, "api_key": "api_key", "encrypt": False},
        {"environment_id": "environment_id", "api_key": 0, "encrypt": False},
        {
            "environment_id": "environment_id",
            "api_key": "api_key",
            "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
            "endpoint": "not a url",
        },
        {
            "environment_id": "environment_id",
            "api_key": "api_key",
            "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
            "endpoint": 1,
        },
    ],
)
@pytest.mark.error_path
def test_invalid_storage(storage_params):
    StorageWithEnv.when.called_with(**storage_params).should.throw(ValidationError)
