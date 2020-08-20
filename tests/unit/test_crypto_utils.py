import pytest
import sure  # noqa: F401

from incountry import decrypt_record, encrypt_record, get_salted_hash, InCrypto, StorageClientException

from incountry.crypto_utils import hash, is_json


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
    "crypto,record,error", [(None, {}, "'crypto' argument should be an instance of InCrypto. Got <class 'NoneType'>")],
)
@pytest.mark.happy_path
def test_decrypt_record_args_validation(crypto, record, error):
    decrypt_record.when.called_with(crypto, record).should.have.raised(StorageClientException, error)


@pytest.mark.parametrize(
    "data,result", [("test", False), ('"test"', True), ("1", True), ('{"test": 42}', True), ("42", True)],
)
@pytest.mark.happy_path
def test_is_json(data, result):
    assert is_json(data) == result


@pytest.mark.happy_path
def test_hash():
    assert PREPARED_HASH["hash"] == hash(PREPARED_HASH["plaintext"])
