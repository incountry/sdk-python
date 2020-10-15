import uuid
import json
import os
from datetime import datetime
import io

import pytest
import sure  # noqa: F401
import httpretty
from requests_toolbelt import MultipartDecoder

from incountry import (
    Storage,
    StorageServerException,
    StorageClientException,
    SecretKeyAccessor,
    get_salted_hash,
)

from ..utils import (
    get_test_records,
    get_random_str,
    get_attachment_meta_valid_response,
    get_attachment_meta_invalid_responses,
)

POPAPI_URL = "https://popapi.com:8082"
COUNTRY = "us"
SECRET_KEY = "password"

TEST_RECORDS = get_test_records()


def json_converter(o):
    if isinstance(o, datetime):
        return o.__str__()


def get_default_find_response(count, data, total=None):
    total = count if total is None else total
    return {
        "meta": {"total": total, "count": count, "limit": 100, "offset": 0},
        "data": data,
    }


def get_key_hash(key):
    return get_salted_hash(key, "test")


@pytest.fixture()
def client():
    def cli(
        encrypt=True,
        endpoint=POPAPI_URL,
        secret_accessor=SecretKeyAccessor(lambda: SECRET_KEY),
        custom_encryption=None,
        environment_id="test",
        **kwargs,
    ):
        return Storage(
            encrypt=encrypt,
            debug=True,
            environment_id=environment_id,
            api_key="test",
            endpoint=endpoint,
            secret_key_accessor=secret_accessor,
            custom_encryption_configs=custom_encryption,
            **kwargs,
        )

    return cli


@httpretty.activate
@pytest.mark.parametrize("response", [get_attachment_meta_valid_response()])
@pytest.mark.parametrize("upsert", [True, False])
@pytest.mark.parametrize("mime_type", [None, "application/python"])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_add_attachment_by_filepath(client, response, upsert, mime_type, encrypt):
    with open(__file__, "rb") as f:
        original_file_body = f.read()
        f.seek(0)

        record_key = str(uuid.uuid1())
        record_key_hash = get_key_hash(record_key)

        httpretty.register_uri(
            httpretty.PUT if upsert else httpretty.POST,
            f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments",
            body=json.dumps(response, default=json_converter),
        )

        params = {"country": COUNTRY, "record_key": record_key, "file": __file__, "upsert": upsert}
        if mime_type is not None:
            params["mime_type"] = mime_type

        res = client(encrypt).add_attachment(**params)

        last_request = httpretty.last_request()
        decoder = MultipartDecoder(last_request.body, last_request.headers["Content-Type"])
        assert decoder.parts[0].content == original_file_body
        if mime_type is not None:
            assert decoder.parts[0].headers[b"Content-Type"] == mime_type.encode("utf-8")

        res.should.have.key("attachment_meta")
        assert res["attachment_meta"] == response


@httpretty.activate
@pytest.mark.parametrize(
    "file_body, response",
    [
        (b"test data", dict(get_attachment_meta_valid_response(), **{"size": len(b"test data")})),
        (b"", dict(get_attachment_meta_valid_response(), **{"size": 0})),
    ],
)
@pytest.mark.parametrize("upsert", [True, False])
@pytest.mark.parametrize("mime_type", [None, "application/python"])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_add_attachment_by_file_object(client, file_body, response, upsert, mime_type, encrypt):
    f = io.BytesIO(file_body)

    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.PUT if upsert else httpretty.POST,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments",
        body=json.dumps(response, default=json_converter),
    )

    params = {"country": COUNTRY, "record_key": record_key, "file": f, "upsert": upsert}
    if mime_type is not None:
        params["mime_type"] = mime_type

    res = client(encrypt).add_attachment(**params)

    last_request = httpretty.last_request()
    decoder = MultipartDecoder(last_request.body, last_request.headers["Content-Type"])
    assert decoder.parts[0].content == file_body
    if mime_type is not None:
        assert decoder.parts[0].headers[b"Content-Type"] == mime_type.encode("utf-8")

    res.should.have.key("attachment_meta")
    assert res["attachment_meta"] == response


@httpretty.activate
@pytest.mark.parametrize(
    "method_params",
    [
        {},
        {"country": COUNTRY},
        {"country": COUNTRY, "record_key": str(uuid.uuid1())},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file": "non existing path"},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file": 123},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file": open(__file__, "ab")},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file": __file__, "upsert": 123},
    ],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.error_path
def test_add_attachment_invalid_input(client, method_params, encrypt):
    client(encrypt).add_attachment.when.called_with(**method_params)

    assert len(httpretty.latest_requests()) == 0


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [get_attachment_meta_valid_response()],
)
@pytest.mark.happy_path
def test_get_attachment(client, response):
    with open(__file__, "rb") as f:
        original_file_body = f.read()
        filename = os.path.basename(__file__)

        file_id = get_random_str()
        record_key = str(uuid.uuid1())
        record_key_hash = get_key_hash(record_key)

        httpretty.register_uri(
            httpretty.GET,
            f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}",
            body=original_file_body,
            content_disposition=f"$attachment; filename*=UTF-8''{filename}",
        )

        res = client().get_attachment_file(country=COUNTRY, record_key=record_key, file_id=file_id)["attachment_data"]

        assert res["filename"] == filename
        assert res["file"].read() == original_file_body


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [get_attachment_meta_valid_response()],
)
@pytest.mark.parametrize(
    "headers",
    [{}, {"content_disposition": "attachment; filename=invalid_filename_header.txt"}],
)
@pytest.mark.happy_path
def test_get_attachment_without_filename(client, response, headers):
    with open(__file__, "rb") as f:
        original_file_body = f.read()

        file_id = get_random_str()
        record_key = str(uuid.uuid1())
        record_key_hash = get_key_hash(record_key)

        httpretty.register_uri(
            httpretty.GET,
            f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}",
            body=original_file_body,
            **headers,
        )

        res = client().get_attachment_file(country=COUNTRY, record_key=record_key, file_id=file_id)["attachment_data"]

        assert res["filename"] == "file"
        assert res["file"].read() == original_file_body


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [get_attachment_meta_invalid_responses()[0]],
)
@pytest.mark.error_path
def test_get_attachment_error(client, response):
    with open(__file__, "rb") as f:
        original_file_body = f.read()

        file_id = get_random_str()
        record_key = str(uuid.uuid1())
        record_key_hash = get_key_hash(record_key)

        httpretty.register_uri(
            httpretty.GET,
            f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}",
            body=original_file_body,
            status=500,
        )

        client().get_attachment_file.when.called_with(
            country=COUNTRY, record_key=record_key, file_id=file_id
        ).should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.parametrize(
    "method_params",
    [
        {},
        {"country": COUNTRY},
        {"country": COUNTRY, "record_key": str(uuid.uuid1())},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file_id": 123},
    ],
)
@pytest.mark.error_path
def test_get_attachment_invalid_input(client, method_params):
    client().get_attachment_file.when.called_with(**method_params).should.throw(StorageClientException)


@httpretty.activate
@pytest.mark.parametrize("response", [get_attachment_meta_valid_response()])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_get_attachment_meta(client, response, encrypt):
    file_id = get_random_str()
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}/meta",
        body=json.dumps(response, default=json_converter),
    )

    res = client(encrypt).get_attachment_meta(country=COUNTRY, record_key=record_key, file_id=file_id)

    res.should.have.key("attachment_meta")
    assert res["attachment_meta"] == response


@httpretty.activate
@pytest.mark.parametrize(
    "method_params",
    [
        {},
        {"country": COUNTRY},
        {"country": COUNTRY, "record_key": str(uuid.uuid1())},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file_id": 123},
    ],
)
@pytest.mark.error_path
def test_get_attachment_meta_invalid_input(client, method_params):
    client().get_attachment_meta.when.called_with(**method_params).should.throw(StorageClientException)


@httpretty.activate
@httpretty.activate
@pytest.mark.parametrize(
    "new_meta",
    [
        {"filename": get_random_str()},
        {"mime_type": get_random_str()},
        {"filename": get_random_str(), "mime_type": get_random_str()},
    ],
)
@pytest.mark.parametrize("response", [get_attachment_meta_valid_response()])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_update_attachment_meta(client, new_meta, response, encrypt):
    file_id = get_random_str()
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.PATCH,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}/meta",
        body=json.dumps(response, default=json_converter),
    )

    res = client(encrypt).update_attachment_meta(country=COUNTRY, record_key=record_key, file_id=file_id, **new_meta)

    res.should.have.key("attachment_meta")
    assert res["attachment_meta"] == response

    last_request = httpretty.last_request()
    last_request.parsed_body.should.equal(new_meta)


@httpretty.activate
@pytest.mark.parametrize(
    "method_params",
    [
        {},
        {"country": COUNTRY},
        {"country": COUNTRY, "record_key": str(uuid.uuid1())},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file_id": 123},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file_id": "file_id"},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file_id": "file_id", "filename": 123},
        {"country": COUNTRY, "record_key": str(uuid.uuid1()), "file_id": "file_id", "mime_type": 123},
        {
            "country": COUNTRY,
            "record_key": str(uuid.uuid1()),
            "file_id": "file_id",
            "filename": "new.txt",
            "mime_type": 123,
        },
    ],
)
@pytest.mark.error_path
def test_update_attachment_meta_invalid_input(client, method_params):
    client().update_attachment_meta.when.called_with(**method_params).should.throw(StorageClientException)


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    ["", [], {}],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_delete_attachment(client, response, encrypt):
    file_id = get_random_str()
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.DELETE,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}",
        body=json.dumps(response, default=json_converter),
    )

    res = client(encrypt).delete_attachment(country=COUNTRY, record_key=record_key, file_id=file_id)

    res.should.have.key("success")
    assert res["success"] is True
