import uuid
import os
import sure  # noqa: F401
import pytest

from incountry import Storage

from ..utils import get_valid_test_record

COUNTRY = os.environ.get("INT_INC_COUNTRY")


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
@pytest.mark.parametrize("hash_search_keys", [False], ids=["with plaintext search keys"])
@pytest.mark.parametrize("record_key", [uuid.uuid4().hex])
def test_attachments(storage: Storage, encrypt: bool, use_oauth: bool, record_key: str, clean_up_records) -> None:
    data = get_valid_test_record()
    data["key1"] = "1" * 256
    data["key2"] = "2" * 256
    data["key3"] = "3" * 256
    data["key4"] = "4" * 256
    data["key5"] = "5" * 256
    data["key6"] = "6" * 256
    data["key7"] = "7" * 256
    data["key8"] = "8" * 256
    data["key9"] = "9" * 256
    data["key10"] = "0" * 256
    data["record_key"] = record_key

    write_response = storage.write(country=COUNTRY, **data)
    write_response.should_not.be.none
    write_response.should.have.key("record")
    write_response["record"].should.be.equal(data)
