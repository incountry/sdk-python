import pytest
import sure  # noqa: F401
from pydantic import ValidationError


from incountry.models import (
    HttpRecordBatchWrite,
    HttpRecordDelete,
    HttpRecordFind,
    HttpRecordRead,
    HttpRecordWrite,
    HttpAttachmentMeta,
)

from ..utils import (
    get_test_records,
    get_random_int,
    get_attachment_meta_valid_response,
    get_attachment_meta_invalid_responses,
    get_random_datetime,
    get_random_str,
    get_random_mime_type,
)


TEST_RECORDS = get_test_records()


@pytest.mark.parametrize(
    "body", [{}, [], ""],
)
@pytest.mark.error_path
def test_delete_valid_body(body):
    HttpRecordDelete.when.called_with(body=body).should_not.throw(ValidationError)


@pytest.mark.parametrize(
    "body", [True, {"record_key": "record_key"}],
)
@pytest.mark.error_path
def test_delete_invalid_body(body):
    HttpRecordDelete.when.called_with(body=body).should.throw(ValidationError)


@pytest.mark.parametrize(
    "body", ["OK"],
)
@pytest.mark.happy_path
def test_write_valid_body(body):
    HttpRecordWrite.when.called_with(body=body).should_not.throw(ValidationError)


@pytest.mark.parametrize(
    "body", [{}, [], True, "", {"record_key": "record_key"}],
)
@pytest.mark.error_path
def test_write_invalid_body(body):
    HttpRecordWrite.when.called_with(body=body).should.throw(ValidationError)


@pytest.mark.parametrize(
    "body", ["OK"],
)
@pytest.mark.happy_path
def test_batch_write_valid_body(body):
    HttpRecordBatchWrite.when.called_with(body=body).should_not.throw(ValidationError)


@pytest.mark.parametrize(
    "body", [{}, [], True, "", {"record_key": "record_key"}],
)
@pytest.mark.error_path
def test_batch_write_invalid_body(body):
    HttpRecordBatchWrite.when.called_with(body=body).should.throw(ValidationError)


@pytest.mark.parametrize(
    "body",
    [
        {
            "meta": {"count": 1, "limit": 1, "offset": 1, "total": 1},
            "data": [{"record_key": "record_key", "version": 1}],
        },
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": []},
    ],
)
@pytest.mark.happy_path
def test_find_valid_response(body):
    HttpRecordFind.when.called_with(body=body).should_not.throw(ValidationError)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"meta": {"count": 1}, "data": []},
        {"meta": {"count": 1, "limit": 1}, "data": []},
        {"meta": {"count": 1, "limit": 1, "offset": 1}, "data": []},
        {"meta": {"count": 0, "limit": 0, "offset": 0, "total": 0}, "data": []},
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": {}},
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": ["not a record"]},
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": [{"not_a_record_key": 0}]},
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": [{"not_a_record_key": 0}]},
        {
            "meta": {"count": 1, "limit": 1, "offset": 1, "total": 1},
            "data": [{"record_key": "key_for_record_with_invalid_version", "version": "good version"}],
        },
        {"data": [{"record_key": "record_key", "version": 1}]},
    ],
)
@pytest.mark.error_path
def test_find_invalid_response(body):
    HttpRecordFind.when.called_with(body=body).should.throw(ValidationError)


@pytest.mark.parametrize(
    "body",
    [
        *TEST_RECORDS,
        {**TEST_RECORDS[-1], "version": get_random_int()},
        {**TEST_RECORDS[-1], "version": get_random_int(), "is_encrypted": True},
        {**TEST_RECORDS[-1], "version": get_random_int(), "is_encrypted": False},
        {**TEST_RECORDS[-1], "attachments": [get_attachment_meta_valid_response()]},
        {
            **TEST_RECORDS[-1],
            "attachments": [get_attachment_meta_valid_response(), get_attachment_meta_valid_response()],
        },
    ],
)
@pytest.mark.happy_path
def test_read_valid_response(body):
    HttpRecordRead.when.called_with(body=body).should_not.throw(ValidationError)


@pytest.mark.parametrize(
    "body",
    [
        {},
        [],
        True,
        "",
        {**TEST_RECORDS[-1], "version": "invalid version"},
        {**TEST_RECORDS[-1], "version": get_random_int(), "is_encrypted": 1},
        {**TEST_RECORDS[-1], "version": get_random_int(), "is_encrypted": "yes"},
        {**TEST_RECORDS[-1], "version": get_random_int(), "is_encrypted": []},
        {**TEST_RECORDS[-1], "version": get_random_int(), "is_encrypted": {}},
        {**TEST_RECORDS[-1], "version": get_random_int(), "is_encrypted": ()},
        {**TEST_RECORDS[-1], "attachments": get_attachment_meta_invalid_responses()},
    ],
)
@pytest.mark.error_path
def test_read_invalid_response(body):
    HttpRecordRead.when.called_with(body=body).should.throw(ValidationError)


@pytest.mark.parametrize(
    "body", [get_attachment_meta_valid_response()],
)
@pytest.mark.happy_path
def test_attachment_meta_valid_response(body):
    HttpAttachmentMeta.when.called_with(body=body).should_not.throw(ValidationError)


@pytest.mark.parametrize("body", get_attachment_meta_invalid_responses())
@pytest.mark.error_path
def test_attachment_meta_invalid_response(body):
    HttpAttachmentMeta.when.called_with(body=body).should.throw(ValidationError)
