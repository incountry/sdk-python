import uuid
import json

import pytest
import sure  # noqa: F401
import httpretty

from incountry import (
    StorageServerException,
    HttpClient,
    get_salted_hash,
)

from incountry.__version__ import __version__

POPAPI_URL = "https://popapi.com:8082"
COUNTRY = "us"


def get_key_hash(key):
    return get_salted_hash(key, "test")


@pytest.fixture()
def client():
    def cli(endpoint=POPAPI_URL, options={}):
        return HttpClient(env_id="test", api_key="test", endpoint=endpoint, debug=True, options=options)

    return cli


@pytest.mark.parametrize(
    "kwargs", [{"env_id": "env_id", "api_key": "api_key", "endpoint": "http://popapi.com", "debug": True}],
)
@pytest.mark.happy_path
def test_http_client_constructor(kwargs):
    client_instance = HttpClient(**kwargs)

    for arg in kwargs:
        assert kwargs[arg] == getattr(client_instance, arg)


@pytest.mark.parametrize(
    "kwargs", [{"env_id": "env_id", "api_key": "api_key", "endpoint": "http://popapi.com", "debug": True}],
)
@pytest.mark.happy_path
def test_http_client_headers(kwargs):
    client_instance = HttpClient(**kwargs)

    headers = client_instance.get_headers()
    assert headers["Authorization"] == f"Bearer {kwargs['api_key']}"
    assert headers["x-env-id"] == kwargs["env_id"]
    assert headers["Content-Type"] == "application/json"
    assert headers["User-Agent"] == f"SDK-Python/{__version__}"


@httpretty.activate
@pytest.mark.parametrize(
    "response_code", [400, 401, 402, 403, 404, 500, 501, 502, 503],
)
@pytest.mark.error_path
def test_request_invalid_response_code(client, response_code):
    httpretty.register_uri(
        httpretty.GET, POPAPI_URL + "/v2/storage/records/" + COUNTRY, status=response_code,
    )

    client().request.when.called_with(country=COUNTRY, path="", method="GET").should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.parametrize(
    "response", ["OK"],
)
@pytest.mark.happy_path
def test_write_valid_response(client, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body=json.dumps(response),
    )

    res = client().write(country=COUNTRY, data="data")
    assert res == response


@httpretty.activate
@pytest.mark.parametrize(
    "response", [{}, [], True, "", {"key": "key"}],
)
@pytest.mark.error_path
def test_write_invalid_response(client, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body=json.dumps(response),
    )

    client().write.when.called_with(country=COUNTRY, data="data").should.have.raised(
        StorageServerException, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "response", ["OK"],
)
@pytest.mark.happy_path
def test_batch_write_valid_response(client, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body=json.dumps(response),
    )

    res = client().batch_write(country=COUNTRY, data="data")
    assert res == response


@httpretty.activate
@pytest.mark.parametrize(
    "response", [{}, [], True, "", {"key": "key"}],
)
@pytest.mark.error_path
def test_batch_write_invalid_response(client, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body=json.dumps(response),
    )

    client().batch_write.when.called_with(country=COUNTRY, data="data").should.have.raised(
        StorageServerException, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "response", [{"key": "key", "version": 1}],
)
@pytest.mark.happy_path
def test_read_valid_response(client, response):
    key = str(uuid.uuid1())
    key_hash = get_key_hash(key)

    httpretty.register_uri(
        httpretty.GET, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + key_hash, body=json.dumps(response),
    )

    res = client().read(country=COUNTRY, key=key_hash)
    assert res == response


@httpretty.activate
@pytest.mark.parametrize(
    "response", [{}, [], True, "", {"key": "key"}],
)
@pytest.mark.error_path
def test_read_invalid_response(client, response):
    key = str(uuid.uuid1())
    key_hash = get_key_hash(key)

    httpretty.register_uri(
        httpretty.GET, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + key_hash, body=json.dumps(response),
    )

    client().read.when.called_with(country=COUNTRY, key=key_hash).should.have.raised(
        StorageServerException, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": [{"key": "key", "version": 1}]},
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": []},
    ],
)
@pytest.mark.happy_path
def test_find_valid_response(client, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find", body=json.dumps(response)
    )

    res = client().find(country=COUNTRY, data="data")
    assert res == response


@httpretty.activate
@pytest.mark.parametrize(
    "query", [{"key": "key1"}],
)
@httpretty.activate
@pytest.mark.parametrize(
    "response",
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
            "data": [{"key": "key_for_record_without_version"}],
        },
        {"data": [{"key": "key", "version": 1}]},
    ],
)
@pytest.mark.error_path
def test_find_invalid_response(client, query, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find", body=json.dumps(response)
    )

    client().find.when.called_with(country=COUNTRY, data="data").should.have.raised(
        StorageServerException, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "response", ["", [], {}],
)
@pytest.mark.happy_path
def test_delete_valid_response(client, response):
    key = str(uuid.uuid1())
    key_hash = get_key_hash(key)

    httpretty.register_uri(
        httpretty.DELETE, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + key_hash, body=json.dumps(response),
    )

    res = client().delete(country=COUNTRY, key=key_hash)
    assert res == response


@httpretty.activate
@pytest.mark.parametrize(
    "response", [True, {"key": "key"}],
)
@pytest.mark.error_path
def test_delete_invalid_response(client, response):
    key = str(uuid.uuid1())
    key_hash = get_key_hash(key)

    httpretty.register_uri(
        httpretty.DELETE, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + key_hash, body=json.dumps(response),
    )

    client().delete.when.called_with(country=COUNTRY, key=key_hash).should.have.raised(
        StorageServerException, "HTTP Response validation failed"
    )
