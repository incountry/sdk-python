import uuid
import os
import sure  # noqa: F401
import pytest

from incountry import Storage
from incountry.models import MAX_LEN_NON_HASHED

from ..utils import get_valid_test_record

COUNTRY = os.environ.get("INT_INC_COUNTRY")


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
@pytest.mark.parametrize("hash_search_keys", [False], ids=["with plaintext search keys"])
@pytest.mark.parametrize("record_key", [uuid.uuid4().hex])
def test_non_hashed_mode(storage: Storage, record_key: str, clean_up_records) -> None:
    data = get_valid_test_record()
    data["key1"] = "1" * MAX_LEN_NON_HASHED
    data["key2"] = "2" * MAX_LEN_NON_HASHED
    data["key3"] = "3" * MAX_LEN_NON_HASHED
    data["key4"] = "4" * MAX_LEN_NON_HASHED
    data["key5"] = "5" * MAX_LEN_NON_HASHED
    data["key6"] = "6" * MAX_LEN_NON_HASHED
    data["key7"] = "7" * MAX_LEN_NON_HASHED
    data["key8"] = "8" * MAX_LEN_NON_HASHED
    data["key9"] = "9" * MAX_LEN_NON_HASHED
    data["key10"] = "0" * MAX_LEN_NON_HASHED
    data["record_key"] = record_key

    write_response = storage.write(country=COUNTRY, **data)
    write_response.should_not.be.none
    write_response.should.have.key("record")
    write_response["record"].should.be.equal(data)


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
@pytest.mark.parametrize("hash_search_keys", [False], ids=["with plaintext search keys"])
@pytest.mark.parametrize("record_key", [uuid.uuid4().hex])
def test_search_keys(storage: Storage, record_key: str, clean_up_records) -> None:
    data = get_valid_test_record()
    data["key1"] = "some_meaningful_information1"
    data["key2"] = "some_meaningful_information2_with_suffix"
    data["key3"] = "information3_of_some_importance"
    data["record_key"] = record_key

    storage.write(country=COUNTRY, **data)

    find_response1 = storage.find_one(country=COUNTRY, search_keys="information1")
    find_response2 = storage.find_one(country=COUNTRY, search_keys="information2")
    find_response3 = storage.find_one(country=COUNTRY, search_keys="information3")

    assert find_response1["record"]["record_key"] == record_key
    assert find_response2["record"]["record_key"] == record_key
    assert find_response3["record"]["record_key"] == record_key
