import pytest
import sure  # noqa: F401
from pydantic import ValidationError
from io import BufferedIOBase

from incountry.models import AttachmentCreate, AttachmentMetaUpdate, AttachmentRequest

from ..utils import (
    get_test_records,
    get_random_str,
)


TEST_RECORDS = get_test_records()


@pytest.mark.parametrize(
    "data",
    [
        {"record_key": get_random_str(), "upsert": True, "file": __file__},
        {"record_key": get_random_str(), "upsert": False, "file": __file__, "mime_type": "application/python"},
        {"record_key": get_random_str(), "upsert": True, "file": open(__file__, "rb")},
        {
            "record_key": get_random_str(),
            "upsert": True,
            "file": open(__file__, "rb"),
            "mime_type": "application/python",
        },
    ],
)
@pytest.mark.happy_path
def test_attachment_create_valid_data(data):
    model_instance = AttachmentCreate(**data)
    assert model_instance.record_key == data["record_key"]
    assert model_instance.upsert == data["upsert"]
    assert isinstance(model_instance.file, BufferedIOBase)

    if not isinstance(data["file"], BufferedIOBase):
        with open(str(data["file"]), "rb") as input_file:
            assert model_instance.file.read() == input_file.read()


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"record_key": "", "upsert": True, "file": open(__file__, "rb")},
        {"record_key": 123, "upsert": True, "file": __file__},
        {"record_key": get_random_str(), "upsert": 123, "file": __file__},
        {"record_key": get_random_str(), "upsert": True, "file": 123},
        {"record_key": get_random_str(), "upsert": True, "file": __file__, "mime_type": ""},
    ],
)
@pytest.mark.error_path
def test_attachment_create_invalid_data(data):
    AttachmentCreate.when.called_with(**data).should.throw(ValidationError)


@pytest.mark.parametrize(
    "data",
    [{"record_key": get_random_str(), "file_id": get_random_str()}],
)
@pytest.mark.happy_path
def test_attachment_request_valid_data(data):
    model_instance = AttachmentRequest(**data)
    assert model_instance.record_key == data["record_key"]
    assert model_instance.file_id == data["file_id"]


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"record_key": get_random_str(), "file_id": 123},
        {"record_key": 123, "file_id": get_random_str()},
        {"record_key": get_random_str(), "file_id": ""},
        {"record_key": "", "file_id": get_random_str()},
    ],
)
@pytest.mark.error_path
def test_attachment_request_invalid_data(data):
    AttachmentRequest.when.called_with(**data).should.throw(ValidationError)


@pytest.mark.parametrize(
    "data",
    [
        {"filename": get_random_str(), "mime_type": "application/json"},
        {"filename": get_random_str()},
        {"mime_type": "application/json"},
        {"filename": get_random_str(), "mime_type": "application/octet-stream"},
    ],
)
@pytest.mark.happy_path
def test_attachment_meta_update_valid_data(data):
    model_instance = AttachmentMetaUpdate(**data)
    for key in data:
        assert getattr(model_instance, key) == data[key]


@pytest.mark.parametrize(
    "data",
    [{}, {"filename": "", "mime_type": "application/json"}, {"filename": get_random_str(), "mime_type": ""}],
)
@pytest.mark.error_path
def test_attachment_meta_update_invalid_data(data):
    AttachmentMetaUpdate.when.called_with(**data).should.throw(ValidationError)
