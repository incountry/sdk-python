import os
import uuid

import pytest
import sure  # noqa: F401
from pydantic import ValidationError


from incountry.models import (
    Country,
    CustomEncryptionConfig,
    CustomEncryptionConfigMethodValidation,
    FindFilter,
    InCrypto,
    Record,
    RecordFromServer,
    RecordListForBatch,
    SecretsData,
    SecretsDataForDefaultEncryption,
    SecretsDataForCustomEncryption,
    SecretKeyAccessor as SecretKeyAccessorModel,
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

VALID_STORAGE_PARAMS = {
    "environment_id": "environment_id",
    "api_key": "api_key",
    "encrypt": True,
    "endpoint": "https://us.api.incountry.io",
    "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
    "custom_encryption_configs": None,
    "debug": True,
}

VALID_CUSTOM_ENCRYPTION_CONFIG = {
    "encrypt": lambda input, key, key_version: input,
    "decrypt": lambda input, key, key_version: input,
    "version": "1",
}


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
    "config",
    [
        {**VALID_CUSTOM_ENCRYPTION_CONFIG, "isCurrent": True},
        {**VALID_CUSTOM_ENCRYPTION_CONFIG, "isCurrent": False},
        {**VALID_CUSTOM_ENCRYPTION_CONFIG, "version": "For Prod", "isCurrent": True},
    ],
)
@pytest.mark.happy_path
def test_valid_custom_enc_config(config):
    CustomEncryptionConfig.when.called_with(**config).should_not.throw(Exception)


@pytest.mark.parametrize(
    "config, error_text",
    [
        ({**VALID_CUSTOM_ENCRYPTION_CONFIG, "encrypt": True}, "is not callable",),
        ({**VALID_CUSTOM_ENCRYPTION_CONFIG, "decrypt": True}, "is not callable",),
        ({**VALID_CUSTOM_ENCRYPTION_CONFIG, "version": 1}, "str type expected",),
        ({**VALID_CUSTOM_ENCRYPTION_CONFIG, "isCurrent": 1}, "value is not a valid boolean",),
        ({**VALID_CUSTOM_ENCRYPTION_CONFIG, "encrypt": lambda text, key, key_version: "text"}, "Invalid signature",),
        ({**VALID_CUSTOM_ENCRYPTION_CONFIG, "decrypt": lambda text, key, key_version: "text"}, "Invalid signature",),
    ],
)
@pytest.mark.error_path
def test_invalid_custom_encryption_config(config, error_text):
    CustomEncryptionConfig.when.called_with(**config).should.throw(ValidationError, error_text)


@pytest.mark.parametrize(
    "config",
    [
        {**VALID_CUSTOM_ENCRYPTION_CONFIG, "isCurrent": True, "key": b"password", "keyVersion": 1},
        {**VALID_CUSTOM_ENCRYPTION_CONFIG, "isCurrent": False, "key": b"password", "keyVersion": 1},
        {
            **VALID_CUSTOM_ENCRYPTION_CONFIG,
            "version": "For Prod",
            "isCurrent": True,
            "key": b"password",
            "keyVersion": 1,
        },
    ],
)
@pytest.mark.happy_path
def test_valid_custom_enc_config_method_validation(config):
    CustomEncryptionConfigMethodValidation.when.called_with(**config).should_not.throw(Exception)


@pytest.mark.parametrize(
    "config, error_text",
    [
        ({**VALID_CUSTOM_ENCRYPTION_CONFIG, "key": 1, "keyVersion": 1}, "value is not valid bytes"),
        ({**VALID_CUSTOM_ENCRYPTION_CONFIG, "key": "password", "keyVersion": "1"}, "value is not a valid integer"),
        (
            {
                **VALID_CUSTOM_ENCRYPTION_CONFIG,
                "encrypt": lambda input, key, key_version: exec("raise Exception('encrypt error')"),
                "key": b"password",
                "keyVersion": 1,
            },
            "should return str. Threw exception instead",
        ),
        (
            {
                **VALID_CUSTOM_ENCRYPTION_CONFIG,
                "decrypt": lambda input, key, key_version: exec("raise Exception('encrypt error')"),
                "key": b"password",
                "keyVersion": 1,
            },
            "should return str. Threw exception instead",
        ),
        (
            {
                **VALID_CUSTOM_ENCRYPTION_CONFIG,
                "encrypt": lambda input, key, key_version: 1,
                "key": b"password",
                "keyVersion": 1,
            },
            "should return str",
        ),
        (
            {
                **VALID_CUSTOM_ENCRYPTION_CONFIG,
                "decrypt": lambda input, key, key_version: 1,
                "key": b"password",
                "keyVersion": 1,
            },
            "should return str",
        ),
        (
            {
                **VALID_CUSTOM_ENCRYPTION_CONFIG,
                "decrypt": lambda input, key, key_version: input + "1",
                "key": b"password",
                "keyVersion": 1,
            },
            "decrypted data doesn't match the original input",
        ),
    ],
)
@pytest.mark.error_path
def test_invalid_custom_enc_config_method_validation(config, error_text):
    CustomEncryptionConfigMethodValidation.when.called_with(**config).should.throw(ValidationError, error_text)


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
    "params",
    [
        {},
        {"secret_key_accessor": SecretKeyAccessor(lambda: "password")},
        {
            "secret_key_accessor": SecretKeyAccessor(
                lambda: {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1}]}
            )
        },
        {
            "secret_key_accessor": SecretKeyAccessor(
                lambda: {
                    "currentVersion": 1,
                    "secrets": [{"secret": "12345678901234567890123456789012", "version": 1, "isKey": True}],
                }
            )
        },
        {
            "secret_key_accessor": SecretKeyAccessor(
                lambda: {
                    "currentVersion": 1,
                    "secrets": [{"secret": "123", "version": 1, "isKey": True, "isForCustomEncryption": True}],
                }
            ),
            "custom_encryption_configs": [
                {
                    "encrypt": lambda input, key, key_version: input,
                    "decrypt": lambda input, key, key_version: input,
                    "version": "test",
                    "isCurrent": True,
                }
            ],
        },
        {
            "secret_key_accessor": SecretKeyAccessor(
                lambda: {
                    "currentVersion": 1,
                    "secrets": [{"secret": "123", "version": 1, "isKey": True, "isForCustomEncryption": True}],
                }
            ),
            "custom_encryption_configs": [
                {
                    "encrypt": lambda input, key, key_version: input,
                    "decrypt": lambda input, key, key_version: input,
                    "version": "test",
                }
            ],
        },
    ],
)
@pytest.mark.happy_path
def test_valid_incrypto(params):
    InCrypto.when.called_with(**params).should_not.throw(Exception)


@pytest.mark.parametrize(
    "secret_key_accessor",
    [
        (),
        {},
        [],
        "",
        "password",
        0,
        1,
        SecretKeyAccessor(lambda: True),
        SecretKeyAccessor(lambda: {"currentVersion": 1, "secrets": []}),
    ],
)
@pytest.mark.happy_path
def test_invalid_secret_key_accessor_param_for_incrypto(secret_key_accessor):
    InCrypto.when.called_with(**{"secret_key_accessor": secret_key_accessor}).should.throw(ValidationError)


@pytest.mark.parametrize(
    "custom_encryption_configs",
    [
        (),
        {},
        [],
        "",
        "password",
        0,
        1,
        [
            {**VALID_CUSTOM_ENCRYPTION_CONFIG, "version": "same version"},
            {**VALID_CUSTOM_ENCRYPTION_CONFIG, "version": "same version"},
        ],
        [
            {**VALID_CUSTOM_ENCRYPTION_CONFIG, "version": "version1", "isCurrent": True},
            {**VALID_CUSTOM_ENCRYPTION_CONFIG, "version": "version2", "isCurrent": True},
        ],
    ],
)
@pytest.mark.error_path
def test_invalid_custom_encryption_configs_param_for_incrypto(custom_encryption_configs):
    InCrypto.when.called_with(
        **{
            "secret_key_accessor": SecretKeyAccessor(lambda: "password"),
            "custom_encryption_configs": custom_encryption_configs,
        }
    ).should.throw(ValidationError)


@pytest.mark.error_path
def test_invalid_params_for_incrypto():
    InCrypto.when.called_with(
        **{
            "secret_key_accessor": None,
            "custom_encryption_configs": [
                {
                    "encrypt": lambda input, key, key_version: input,
                    "decrypt": lambda input, key, key_version: input,
                    "version": "some version",
                }
            ],
        }
    ).should.throw(ValidationError)


@pytest.mark.error_path
def test_no_suitable_enc_key_for_custom_encryption_for_incrypto():
    secret_accessor = SecretKeyAccessor(lambda: "password")

    def enc(input, key, key_version):
        raise Exception("Unsupported key")

    InCrypto.when.called_with(
        **{
            "secret_key_accessor": secret_accessor,
            "custom_encryption_configs": [
                {"encrypt": enc, "decrypt": lambda input, key, key_version: input, "version": "some version"}
            ],
        }
    ).should.throw(ValidationError, "should return str. Threw exception instead")


@pytest.mark.error_path
def test_no_suitable_dec_key_for_custom_encryption_for_incrypto():
    secret_accessor = SecretKeyAccessor(lambda: "password")

    def dec(input, key, key_version):
        raise Exception("Unsupported key")

    InCrypto.when.called_with(
        **{
            "secret_key_accessor": secret_accessor,
            "custom_encryption_configs": [
                {"decrypt": dec, "encrypt": lambda input, key, key_version: input, "version": "some version"}
            ],
        }
    ).should.throw(ValidationError, "should return str. Threw exception instead")


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
                {"secret": "12345678901234567890123456789012", "version": 2, "isKey": True},
            ],
        },
        {
            "currentVersion": 2,
            "secrets": [{"secret": "password1", "version": 1}, {"secret": "password2", "version": 2}],
        },
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
        {"currentVersion": 1, "secrets": [{"secret": "short key", "version": 1, "isKey": True}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isForCustomEncryption": True}]},
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
        ValidationError, "none of the secret versions match currentVersion"
    )


@pytest.mark.parametrize(
    "keys_data",
    [
        {
            "currentVersion": 1,
            "secrets": [{"secret": "12345678901234567890123456789012", "version": 1, "isKey": True}],
        },
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1}]},
    ],
)
@pytest.mark.error_path
def test_valid_secrets_data_for_default_encryption(keys_data):
    item = SecretsDataForDefaultEncryption(**keys_data)

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
        {
            "currentVersion": 1,
            "secrets": [{"secret": "password", "version": 1, "isKey": True, "isForCustomEncryption": True}],
        }
    ],
)
@pytest.mark.error_path
def test_invalid_secrets_data_for_default_encryption(keys_data):
    SecretsDataForDefaultEncryption.when.called_with(**keys_data).should.have.raised(
        ValidationError, "found custom encryption keys when not using custom encryption"
    )


@pytest.mark.parametrize(
    "keys_data",
    [
        {
            "currentVersion": 1,
            "secrets": [{"secret": "password1", "version": 1, "isKey": True, "isForCustomEncryption": True}],
        },
    ],
)
@pytest.mark.error_path
def test_valid_secrets_data_for_custom_encryption(keys_data):
    item = SecretsDataForCustomEncryption(**keys_data)

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
    "keys_data", [{"currentVersion": 1, "secrets": [{"secret": "password", "version": 1}]}],
)
@pytest.mark.error_path
def test_invalid_secrets_data_for_custom_encryption(keys_data):
    SecretsDataForCustomEncryption.when.called_with(**keys_data).should.have.raised(
        ValidationError, "custom encryption keys not provided when using custom encryption"
    )


@pytest.mark.happy_path
def text_valid_secret_key_accessor():
    def get_secrets():
        return "password"

    SecretKeyAccessorModel.when.called_with(accessor_function=lambda: "password").should_not.throw(ValidationError)
    SecretKeyAccessorModel.when.called_with(accessor_function=get_secrets).should_not.throw(ValidationError)


@pytest.mark.parametrize(
    "accessor_function", [(), [], {}, 0, 1, "", "password", SecretKeyAccessor],
)
@pytest.mark.error_path
def text_invalid_secret_key_accessor(accessor_function):
    SecretKeyAccessorModel.when.called_with(accessor_function=accessor_function).should.throw(
        ValidationError, "is not callable"
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
        {"environment_id": "environment_id"},
        {"api_key": "api_key"},
        {"encrypt": False},
        {"encrypt": True},
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
    ],
)
@pytest.mark.error_path
def test_invalid_storage(storage_params):
    StorageWithEnv.when.called_with(**storage_params).should.throw(ValidationError)


@pytest.mark.parametrize(
    "secret_key_accessor", [{}, [], (), "", "password", 0, 1, StorageWithEnv],
)
@pytest.mark.error_path
def test_invalid_secret_key_accessor_param_for_storage(secret_key_accessor):
    StorageWithEnv.when.called_with(
        **{**VALID_STORAGE_PARAMS, "secret_key_accessor": secret_key_accessor}
    ).should.throw(ValidationError)


@pytest.mark.parametrize(
    "endpoint", [{}, [], (), "", "not a url", 0, 1, {"url": "http://api.com"}, ["http://api.com"], ("http://api.com",)],
)
@pytest.mark.error_path
def test_invalid_endpoint_param_for_storage(endpoint):
    StorageWithEnv.when.called_with(**{**VALID_STORAGE_PARAMS, "endpoint": endpoint}).should.throw(ValidationError)


@pytest.mark.parametrize(
    "endpoint", ["", "not a url", "1", "0"],
)
@pytest.mark.error_path
def test_invalid_env_endpoint_param_for_storage(endpoint):
    os.environ["INC_ENDPOINT"] = endpoint
    StorageWithEnv.when.called_with(**{**VALID_STORAGE_PARAMS, "endpoint": None}).should.throw(ValidationError)
