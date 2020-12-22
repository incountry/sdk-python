import uuid
import os
import sure  # noqa: F401
import pytest
from datetime import datetime, timezone
from pathlib import Path

from incountry import Storage

from ..utils import get_valid_test_record

COUNTRY = os.environ.get("INT_INC_COUNTRY")


@pytest.mark.parametrize("encrypt", [False], ids=["not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
@pytest.mark.parametrize("record_key", [uuid.uuid4().hex])
def test_attachments(storage: Storage, encrypt: bool, use_oauth: bool, record_key: str, clean_up_records) -> None:
    data = get_valid_test_record()
    data["record_key"] = record_key
    write_response = storage.write(country=COUNTRY, **data)

    record = write_response["record"]

    with open(__file__, "rb") as test_file:
        test_file_name = Path(__file__).name
        test_file_body = test_file.read()
        test_file_len = len(test_file_body)
        start = datetime.now(tz=timezone.utc).replace(microsecond=0)

        # Add Attachment
        attachment_add_res = storage.add_attachment(country=COUNTRY, record_key=record["record_key"], file=__file__)

        attachment_add_res.should.be.a("dict")
        attachment_add_res.should.have.key("attachment_meta")
        meta = attachment_add_res["attachment_meta"]
        meta.should.have.key("size").being.equal(test_file_len)
        meta.should.have.key("mime_type").being.equal("text/x-python")
        meta.should.have.key("filename").being.equal(test_file_name)
        meta.should.have.key("created_at").being.greater_than_or_equal_to(start)
        meta.should.have.key("updated_at").being.greater_than_or_equal_to(start)

        # Get Attachment Meta
        attachment_meta_res = storage.get_attachment_meta(
            country=COUNTRY, record_key=record["record_key"], file_id=meta["file_id"]
        )

        attachment_meta_res.should.be.a("dict")
        attachment_meta_res.should.equal(attachment_add_res)

        # Get Attachment File
        attachment_get_res = storage.get_attachment_file(
            country=COUNTRY, record_key=record["record_key"], file_id=meta["file_id"]
        )

        attachment_meta_res.should.be.a("dict")
        attachment_get_res.should.have.key("attachment_data")

        attachment_data = attachment_get_res["attachment_data"]
        attachment_data.should.be.a("dict")
        attachment_data.should.have.key("file")
        attachment_data.should.have.key("filename").being.equal(test_file_name)
        attachment_data["file"].read().should.equal(test_file_body)

        # Update Attachment Meta
        new_filename = "test.py"
        new_mime_type = "application/python"

        attachment_meta_update_res = storage.update_attachment_meta(
            country=COUNTRY,
            record_key=record["record_key"],
            file_id=meta["file_id"],
            filename=new_filename,
            mime_type=new_mime_type,
        )

        attachment_meta_res.should.be.a("dict")
        attachment_meta_update_res.should.have.key("attachment_meta")
        updated_meta = attachment_meta_update_res["attachment_meta"]
        updated_meta.should.be.a("dict")
        updated_meta.should.have.key("size").being.equal(test_file_len)
        updated_meta.should.have.key("mime_type").being.equal(new_mime_type)
        updated_meta.should.have.key("filename").being.equal(new_filename)
        updated_meta.should.have.key("created_at").being.greater_than_or_equal_to(start)
        updated_meta.should.have.key("updated_at").being.greater_than(meta["updated_at"])

        attachment_meta_res_after_update = storage.get_attachment_meta(
            country=COUNTRY, record_key=record["record_key"], file_id=meta["file_id"]
        )

        attachment_meta_res_after_update.should.equal(attachment_meta_update_res)

        # Delete Attachment Meta
        delete_res = storage.delete_attachment(
            country=COUNTRY, record_key=record["record_key"], file_id=meta["file_id"]
        )
        delete_res.should.be.a("dict")
        delete_res.should.have.key("success").being.equal(True)


@pytest.mark.parametrize("encrypt", [False], ids=["not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
@pytest.mark.parametrize("mime", ["application/python"])
@pytest.mark.parametrize("record_key", [uuid.uuid4().hex])
def test_attachment_with_custom_mime(
    storage: Storage, encrypt: bool, use_oauth: bool, mime: str, record_key: str, clean_up_records
) -> None:
    data = get_valid_test_record()
    data["record_key"] = record_key
    write_response = storage.write(country=COUNTRY, **data)

    record = write_response["record"]

    with open(__file__, "rb") as test_file:
        test_file_name = Path(__file__).name
        test_file_body = test_file.read()
        test_file_len = len(test_file_body)
        start = datetime.now(tz=timezone.utc).replace(microsecond=0)

        # Add Attachment
        attachment_add_res = storage.add_attachment(
            country=COUNTRY, record_key=record["record_key"], file=__file__, mime_type=mime
        )

        attachment_add_res.should.be.a("dict")
        attachment_add_res.should.have.key("attachment_meta")
        meta = attachment_add_res["attachment_meta"]
        meta.should.have.key("size").being.equal(test_file_len)
        meta.should.have.key("mime_type").being.equal(mime)
        meta.should.have.key("filename").being.equal(test_file_name)
        meta.should.have.key("created_at").being.greater_than_or_equal_to(start)
        meta.should.have.key("updated_at").being.greater_than_or_equal_to(start)


@pytest.mark.parametrize("encrypt", [False], ids=["not encrypted"])
@pytest.mark.parametrize("use_oauth", [True, False], ids=["oauth creds", "api key"])
@pytest.mark.parametrize("record_key", [uuid.uuid4().hex])
@pytest.mark.parametrize("filename, filebody", [("Naïve file.txt", "Naïve body".encode("utf-8"))])
def test_attachment_with_unicode_filename(
    storage: Storage,
    encrypt: bool,
    use_oauth: bool,
    record_key: str,
    filename: str,
    filebody: str,
    tempfile: dict,
    clean_up_records,
) -> None:
    data = get_valid_test_record()
    data["record_key"] = record_key
    write_response = storage.write(country=COUNTRY, **data)

    record = write_response["record"]
    attachment_add_res = storage.add_attachment(country=COUNTRY, record_key=record["record_key"], file=tempfile["path"])

    attachment_add_res.should.be.a("dict")
    attachment_add_res.should.have.key("attachment_meta")
    meta = attachment_add_res["attachment_meta"]
    meta.should.have.key("size").being.equal(len(filebody))
    meta.should.have.key("mime_type").being.equal("text/plain")
    meta.should.have.key("filename").being.equal(filename)
