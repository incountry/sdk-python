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
def test_attachments(storage: Storage, encrypt: bool, use_oauth: bool, record_key: str, clean_up_records) -> None:
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
