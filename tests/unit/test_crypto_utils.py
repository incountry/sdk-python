import pytest
import sure  # noqa: F401

from incountry import decrypt_record, encrypt_record, get_salted_hash, InCrypto, StorageClientException

from incountry.crypto_utils import hash, is_json, normalize_key, hash_string_key_value, hash_object_record_keys


PREPARED_HASH = {
    "hash": "e3937cd968975a95dfd22424ac9370c1e1239d97cc23a2310b807bdd8b1c7a9f",
    "plaintext": "InCountry",
}


@pytest.mark.parametrize(
    "value,salt,error",
    [
        (None, "test", "'value' argument should be of type string. Got <class 'NoneType'>"),
        ("test", None, "'salt' argument should be of type string. Got <class 'NoneType'>"),
    ],
)
@pytest.mark.happy_path
def test_hash_custom_key_args_validation(value, salt, error):
    get_salted_hash.when.called_with(value, salt).should.have.raised(StorageClientException, error)


@pytest.mark.parametrize(
    "crypto,record,salt,error",
    [
        (None, {}, "test", "'crypto' argument should be an instance of InCrypto. Got <class 'NoneType'>"),
        (InCrypto(), {}, None, "'salt' argument should be of type string. Got <class 'NoneType'>"),
    ],
)
@pytest.mark.happy_path
def test_encrypt_record_args_validation(crypto, record, salt, error):
    encrypt_record.when.called_with(crypto, record, salt).should.have.raised(StorageClientException, error)


@pytest.mark.parametrize(
    "crypto,record,error",
    [(None, {}, "'crypto' argument should be an instance of InCrypto. Got <class 'NoneType'>")],
)
@pytest.mark.happy_path
def test_decrypt_record_args_validation(crypto, record, error):
    decrypt_record.when.called_with(crypto, record).should.have.raised(StorageClientException, error)


@pytest.mark.parametrize(
    "data,result",
    [("test", False), ('"test"', True), ("1", True), ('{"test": 42}', True), ("42", True)],
)
@pytest.mark.happy_path
def test_is_json(data, result):
    assert is_json(data) == result


@pytest.mark.happy_path
def test_hash():
    assert PREPARED_HASH["hash"] == hash(PREPARED_HASH["plaintext"])


@pytest.mark.parametrize(
    "data,normalize, result",
    [
        (1, False, 1),
        (1, True, 1),
        ("test", False, "test"),
        ("test", True, "test"),
        ("Test", False, "Test"),
        ("Test", True, "test"),
    ],
)
@pytest.mark.happy_path
def test_normalize_key(data, normalize, result):
    assert normalize_key(data, normalize=normalize) == result


@pytest.mark.parametrize(
    "data",
    ["test", ["test1", "test2"]],
)
@pytest.mark.parametrize("normalize", [True, False])
@pytest.mark.happy_path
def test_hash_string_key_value(data, normalize):
    if isinstance(data, list):
        hashed_data_list = [get_salted_hash(normalize_key(x, normalize=normalize), "salt") for x in data]
        assert hash_string_key_value(data, "salt", normalize) == hashed_data_list

    if isinstance(data, str):
        assert hash_string_key_value(data, "salt", normalize) == get_salted_hash(
            normalize_key(data, normalize=normalize), "salt"
        )


@pytest.mark.parametrize(
    "obj, normalize, result",
    [
        (
            {"key1": "Key1", "service_key1": "service_key1", "range_key1": 1},
            False,
            {
                "key1": "Key1",
                "service_key1": hash_string_key_value("service_key1", "salt", normalize=False),
                "range_key1": 1,
            },
        ),
        (
            {"key1": "Key1", "service_key1": "service_key1", "range_key1": 1},
            True,
            {
                "key1": "key1",
                "service_key1": hash_string_key_value("service_key1", "salt", normalize=True),
                "range_key1": 1,
            },
        ),
    ],
)
@pytest.mark.happy_path
def test_hash_object_record_keys_without_search_keys(obj, normalize, result):
    assert hash_object_record_keys(obj, "salt", normalize_keys=normalize, hash_search_keys=False) == result


@pytest.mark.parametrize(
    "obj, normalize, result",
    [
        (
            {"key1": "Key1", "service_key1": "service_key1", "range_key1": 1},
            False,
            {
                "key1": hash_string_key_value("Key1", "salt", normalize=False),
                "service_key1": hash_string_key_value("service_key1", "salt", normalize=False),
                "range_key1": 1,
            },
        ),
        (
            {"key1": "Key1", "service_key1": "service_key1", "range_key1": 1},
            True,
            {
                "key1": hash_string_key_value("key1", "salt", normalize=False),
                "service_key1": hash_string_key_value("service_key1", "salt", normalize=True),
                "range_key1": 1,
            },
        ),
    ],
)
@pytest.mark.happy_path
def test_hash_object_record_keys_with_search_keys(obj, normalize, result):
    assert hash_object_record_keys(obj, "salt", normalize_keys=normalize, hash_search_keys=True) == result
