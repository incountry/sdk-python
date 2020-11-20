import uuid
import json
from urllib.parse import parse_qs
import time
from datetime import datetime
import os
from requests_toolbelt import MultipartDecoder

import pytest
import sure  # noqa: F401
import httpretty


from incountry import (
    StorageServerException,
    HttpClient,
    get_salted_hash,
    ApiKeyTokenClient,
    OAuthTokenClient,
)

from incountry.__version__ import __version__

from ..utils import (
    get_random_str,
    get_attachment_meta_valid_response,
    get_attachment_meta_invalid_responses,
)

POPAPI_URL = "https://popapi.com:8082"
COUNTRY = "us"


def json_converter(o):
    if isinstance(o, datetime):
        return o.__str__()


def get_key_hash(key):
    return get_salted_hash(key, "test")


@pytest.fixture()
def client():
    def cli(env_id="test", endpoint=POPAPI_URL, options={}, token_client=ApiKeyTokenClient("test"), **kwargs):
        return HttpClient(
            env_id=env_id, token_client=token_client, endpoint=endpoint, debug=True, options=options, **kwargs
        )

    return cli


def get_oauth_token_client(
    client_id="client_id", client_secret="client_secret", scope="scope", auth_endpoints=None, token=None, expires_in=300
):
    auth_endpoints = auth_endpoints or OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS

    for key in auth_endpoints.keys():
        httpretty.register_uri(
            httpretty.POST,
            auth_endpoints[key],
            body=json.dumps({"access_token": str(uuid.uuid1()) if token is None else token, "expires_in": expires_in}),
        )
    return OAuthTokenClient(
        client_id=client_id, client_secret=client_secret, scope=scope, auth_endpoints=auth_endpoints
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "env_id": "env_id",
            "token_client": ApiKeyTokenClient("api_key"),
            "endpoint": "http://popapi.com",
            "endpoint_mask": ".private.incountry.io",
            "countries_endpoint": "https://countries.com",
            "debug": True,
        }
    ],
)
@pytest.mark.happy_path
def test_http_client_constructor(kwargs):
    client_instance = HttpClient(**kwargs)

    for arg in kwargs:
        assert kwargs[arg] == getattr(client_instance, arg)


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "env_id": "env_id",
            "token_client": ApiKeyTokenClient("api_key"),
            "endpoint": "http://popapi.com",
            "debug": True,
        }
    ],
)
@pytest.mark.happy_path
def test_http_client_headers(kwargs):
    client_instance = HttpClient(**kwargs)

    headers = client_instance.get_headers(auth_token=kwargs["token_client"].get_token())
    assert headers["Authorization"] == f"Bearer {kwargs['token_client'].get_token()}"
    assert headers["x-env-id"] == kwargs["env_id"]
    assert headers["User-Agent"] == f"SDK-Python/{__version__}"


@httpretty.activate
@pytest.mark.parametrize(
    "response_code",
    [400, 401, 402, 403, 404, 500, 501, 502, 503],
)
@pytest.mark.error_path
def test_request_invalid_response_code(client, response_code):
    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY,
        status=response_code,
    )

    client().request.when.called_with(country=COUNTRY, path="", method="GET").should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    ["OK"],
)
@pytest.mark.happy_path
def test_write_valid_response(client, response):
    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY,
        body=json.dumps(response),
    )

    res = client().write(country=COUNTRY, data="data")
    res.should.contain(response)


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [{}, [], True, "", {"record_key": "record_key"}],
)
@pytest.mark.error_path
@pytest.mark.skip(reason="Disabling until versioning support on PoPAPI")
def test_write_invalid_response(client, response):
    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY,
        body=json.dumps(response),
    )

    client().write.when.called_with(country=COUNTRY, data="data").should.have.raised(
        StorageServerException, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    ["OK"],
)
@pytest.mark.happy_path
def test_batch_write_valid_response(client, response):
    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite",
        body=json.dumps(response),
    )

    res = client().batch_write(country=COUNTRY, data="data")
    assert res == response


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [{}, [], True, "", {"record_key": "record_key"}],
)
@pytest.mark.error_path
@pytest.mark.skip(reason="Disabling until versioning support on PoPAPI")
def test_batch_write_invalid_response(client, response):
    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite",
        body=json.dumps(response),
    )

    client().batch_write.when.called_with(country=COUNTRY, data="data").should.have.raised(
        StorageServerException, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [
        {"record_key": "record_key", "version": 1},
        {"record_key": "record_key", "version": 0},
        {"record_key": "record_key", "version": -1},
        {"record_key": "record_key", "version": None},
    ],
)
@pytest.mark.happy_path
def test_read_valid_response(client, response):
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps(response),
    )

    res = client().read(country=COUNTRY, record_key=record_key_hash)
    assert res.items() >= response.items()


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [{}, [], True, "", {"record_key": "record_key", "version": "invalid version"}],
)
@pytest.mark.error_path
def test_read_invalid_response(client, response):
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps(response),
    )

    client().read.when.called_with(country=COUNTRY, record_key=record_key_hash).should.have.raised(
        StorageServerException, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [
        {
            "meta": {"count": 1, "limit": 1, "offset": 1, "total": 1},
            "data": [{"record_key": "record_key", "version": 1}],
        },
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": []},
    ],
)
@pytest.mark.happy_path
def test_find_valid_response(client, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find", body=json.dumps(response)
    )

    res = client().find(country=COUNTRY, data="data")
    res["meta"].should.equal(response["meta"])
    for i, record in enumerate(res["data"]):
        assert record.items() >= response["data"][i].items()


@pytest.mark.parametrize(
    "query",
    [{"record_key": "key1"}],
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
            "data": [{"record_key": "key_for_record_with_invalid_version", "version": "good version"}],
        },
        {"data": [{"record_key": "record_key", "version": 1}]},
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
    "response",
    ["", [], {}],
)
@pytest.mark.happy_path
def test_delete_valid_response(client, response):
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.DELETE,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps(response),
    )

    res = client().delete(country=COUNTRY, record_key=record_key_hash)
    assert res == response


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [True, {"record_key": "record_key"}],
)
@pytest.mark.error_path
@pytest.mark.skip(reason="Disabling until versioning support on PoPAPI")
def test_delete_invalid_response(client, response):
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.DELETE,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps(response),
    )

    client().delete.when.called_with(country=COUNTRY, record_key=record_key_hash).should.have.raised(
        StorageServerException, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.happy_path
def test_default_oauth_token_client(client):
    env_id = str(uuid.uuid1())

    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps({"record_key": record_key}),
    )

    client(env_id=env_id, token_client=get_oauth_token_client(scope=env_id)).read.when.called_with(
        country=COUNTRY, record_key=record_key_hash
    ).should_not.throw(Exception)

    token_request = httpretty.HTTPretty.latest_requests[-2]
    token_request_body = parse_qs(token_request.body.decode("utf-8"))

    assert token_request_body["audience"][0] == POPAPI_URL
    assert token_request_body["scope"][0] == env_id


@httpretty.activate
@pytest.mark.happy_path
def test_oauth_token_client_custom_endpoint(client):
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps({"record_key": record_key}),
    )

    client(token_client=get_oauth_token_client(auth_endpoints={"default": "https://oauth.com"})).read.when.called_with(
        country=COUNTRY, record_key=record_key_hash
    ).should_not.throw(Exception)


@httpretty.activate
@pytest.mark.happy_path
def test_oauth_token_client_check_token(client):
    token = str(uuid.uuid1())

    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps({"record_key": record_key}),
    )

    client(token_client=get_oauth_token_client(token=token)).read.when.called_with(
        country=COUNTRY, record_key=record_key_hash
    ).should_not.throw(Exception)

    headers = httpretty.last_request().headers

    assert headers["Authorization"] == f"Bearer {token}"


@httpretty.activate
@pytest.mark.happy_path
def test_api_token_client_check_token(client):
    token = str(uuid.uuid1())

    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps({"record_key": record_key}),
    )

    client(token_client=ApiKeyTokenClient(api_key=token)).read.when.called_with(
        country=COUNTRY, record_key=record_key_hash
    ).should_not.throw(Exception)

    headers = httpretty.last_request().headers

    assert headers["Authorization"] == f"Bearer {token}"


@httpretty.activate
@pytest.mark.error_path
def test_api_token_do_not_retry_on_401(client):
    token = str(uuid.uuid1())

    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        body=json.dumps({"record_key": record_key}),
        status=401,
    )

    client(token_client=ApiKeyTokenClient(api_key=token)).read.when.called_with(
        country=COUNTRY, record_key=record_key_hash
    ).should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.happy_path
def test_oauth_token_successful_retry_on_401(client):
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        responses=[
            httpretty.Response(body=json.dumps({"record_key": record_key}), status=401),
            httpretty.Response(body=json.dumps({"record_key": record_key}), status=200),
        ],
    )

    httpretty.register_uri(
        httpretty.POST,
        OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS["default"],
        responses=[
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
        ],
    )

    token_client = OAuthTokenClient(client_id="client_id", client_secret="client_id", scope="scope")

    client(token_client=token_client).read.when.called_with(
        country=COUNTRY, record_key=record_key_hash
    ).should_not.throw(StorageServerException)


@httpretty.activate
@pytest.mark.error_path
def test_oauth_token_unsuccessful_retry_on_401(client):
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record_key_hash,
        responses=[
            httpretty.Response(body=json.dumps({"record_key": record_key}), status=401),
            httpretty.Response(body=json.dumps({"record_key": record_key}), status=401),
        ],
    )

    httpretty.register_uri(
        httpretty.POST,
        OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS["default"],
        responses=[
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
        ],
    )

    token_client = OAuthTokenClient(client_id="client_id", client_secret="client_id", scope="scope")

    client(token_client=token_client).read.when.called_with(country=COUNTRY, record_key=record_key_hash).should.throw(
        StorageServerException
    )

    assert len(httpretty.HTTPretty.latest_requests) == 4


@httpretty.activate
@pytest.mark.happy_path
def test_oauth_work_with_same_token_during_expiration_period(monkeypatch):
    httpretty.register_uri(
        httpretty.POST,
        OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS["default"],
        body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}),
    )

    token_client = OAuthTokenClient(client_id="client_id", client_secret="client_id", scope="scope")

    token_1 = token_client.get_token(audience=POPAPI_URL)
    old_time = time.time
    monkeypatch.setattr(time, "time", lambda: old_time() + 10)
    token_2 = token_client.get_token(audience=POPAPI_URL)

    assert token_1 == token_2


@httpretty.activate
@pytest.mark.happy_path
def test_oauth_fetch_new_token_when_expires(monkeypatch):
    token_ttl = 300

    token_client = OAuthTokenClient(client_id="client_id", client_secret="client_id", scope="scope")

    def get_token():
        httpretty.register_uri(
            httpretty.POST,
            OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS["default"],
            body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": token_ttl}),
        )

        return token_client.get_token(audience=POPAPI_URL)

    token_1 = get_token()
    old_time = time.time
    monkeypatch.setattr(time, "time", lambda: old_time() + token_ttl)
    token_2 = get_token()

    assert token_1 != token_2


@httpretty.activate
@pytest.mark.happy_path
def test_oauth_fetch_new_token_for_different_audiences(monkeypatch):
    token_ttl = 300

    token_client = OAuthTokenClient(client_id="client_id", client_secret="client_id", scope="scope")

    def get_token(audience):
        httpretty.register_uri(
            httpretty.POST,
            OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS["default"],
            body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": token_ttl}),
        )

        return token_client.get_token(audience=audience)

    token_1 = get_token(audience="https://us.api.incountry.io")
    token_2 = get_token(audience="https://ca.api.incountry.io")

    assert token_1 != token_2


@httpretty.activate
@pytest.mark.happy_path
def test_oauth_refetch_token(monkeypatch):
    token_client = OAuthTokenClient(client_id="client_id", client_secret="client_id", scope="scope")

    def get_token(audience):
        httpretty.register_uri(
            httpretty.POST,
            OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS["default"],
            body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}),
        )

        return token_client.get_token(audience=audience, refetch=True)

    token_1 = get_token(audience=POPAPI_URL)
    token_2 = get_token(audience=POPAPI_URL)

    assert token_1 != token_2


@httpretty.activate
@pytest.mark.error_path
def test_oauth_throw_error():
    token_client = OAuthTokenClient(client_id="client_id", client_secret="client_id", scope="scope")

    httpretty.register_uri(
        httpretty.POST,
        OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS["default"],
        body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}),
        status=400,
    )

    token_client.get_token.when.called_with(audience=POPAPI_URL).should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.error_path
def test_httpclient_oauth_throw_error(client):
    http_client = client(token_client=OAuthTokenClient(client_id="client_id", client_secret="client_id", scope="scope"))

    httpretty.register_uri(
        httpretty.POST,
        OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS["default"],
        body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}),
        status=400,
    )

    http_client.read.when.called_with(country="us", record_key="test").should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.parametrize("endpoint_mask", [".private.incountry.io"])
@pytest.mark.parametrize(
    "country, expected_endpoint, expected_audience",
    [
        (
            "ru",
            "https://ru.private.incountry.io",
            "https://ru.private.incountry.io",
        ),
        (
            "ag",
            "https://us.private.incountry.io",
            "https://us.private.incountry.io https://ag.private.incountry.io",
        ),
    ],
)
@pytest.mark.parametrize("countries", [[{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]])
@pytest.mark.happy_path
def test_http_client_endpoint_mask(endpoint_mask, country, expected_endpoint, expected_audience, countries):
    record = {"record_key": "key1", "version": 0}
    client = HttpClient(
        env_id="test",
        endpoint_mask=endpoint_mask,
        token_client=get_oauth_token_client(scope="test"),
    )

    httpretty.register_uri(
        httpretty.GET, HttpClient.DEFAULT_COUNTRIES_ENDPOINT, body=json.dumps({"countries": countries})
    )

    httpretty.register_uri(
        httpretty.GET,
        expected_endpoint + "/v2/storage/records/" + country + "/" + record.get("record_key"),
        body=json.dumps(record),
    )

    client.read.when.called_with(country=country, record_key=record.get("record_key")).should_not.throw(Exception)

    token_request = httpretty.HTTPretty.latest_requests[-2]
    token_request_body = parse_qs(token_request.body.decode("utf-8"))

    read_request = httpretty.HTTPretty.latest_requests[-1]
    read_request_endpoint = "https://" + read_request.headers.get("Host", "")

    assert token_request_body["audience"][0] == expected_audience
    assert read_request_endpoint == expected_endpoint


@httpretty.activate
@pytest.mark.parametrize("endpoint_mask", [".private.incountry.io"])
@pytest.mark.parametrize(
    "endpoint, country, expected_audience",
    [
        (
            "https://super-private.incountry.io",
            "ru",
            "https://super-private.incountry.io https://ru.private.incountry.io",
        ),
        (
            "https://super-private.incountry.io",
            "ag",
            "https://super-private.incountry.io https://ag.private.incountry.io",
        ),
        (
            "https://ru.private.incountry.io",
            "ru",
            "https://ru.private.incountry.io",
        ),
    ],
)
@pytest.mark.parametrize("countries", [[{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]])
@pytest.mark.happy_path
def test_http_client_endpoint_mask_with_endpoint(endpoint_mask, endpoint, country, expected_audience, countries):
    record = {"record_key": "key1", "version": 0}
    client = HttpClient(
        env_id="test",
        endpoint_mask=endpoint_mask,
        endpoint=endpoint,
        token_client=get_oauth_token_client(scope="test"),
    )

    httpretty.register_uri(
        httpretty.GET, HttpClient.DEFAULT_COUNTRIES_ENDPOINT, body=json.dumps({"countries": countries})
    )

    httpretty.register_uri(
        httpretty.GET,
        endpoint + "/v2/storage/records/" + country + "/" + record.get("record_key"),
        body=json.dumps(record),
    )

    client.read.when.called_with(country=country, record_key=record.get("record_key")).should_not.throw(Exception)

    token_request = httpretty.HTTPretty.latest_requests[-2]
    token_request_body = parse_qs(token_request.body.decode("utf-8"))

    assert token_request_body["audience"][0] == expected_audience


@httpretty.activate
@pytest.mark.parametrize(
    "country, is_midpop,  expected_region, countries",
    [
        (
            "ca",
            False,
            "emea",
            [{"id": "RU", "direct": True, "region": "EMEA"}, {"id": "AG", "direct": False}],
        ),
        (
            "ru",
            True,
            "emea",
            [{"id": "RU", "direct": True, "region": "EMEA"}, {"id": "AG", "direct": False}],
        ),
        (
            "ag",
            False,
            "emea",
            [{"id": "RU", "direct": True}, {"id": "AG", "direct": False, "region": "AMER"}],
        ),
        (
            "ag",
            True,
            "emea",
            [{"id": "RU", "direct": True}, {"id": "AG", "direct": True, "region": "AMER"}],
        ),
        (
            "au",
            False,
            "emea",
            [{"id": "RU", "direct": True}, {"id": "AU", "direct": False, "region": "APAC"}],
        ),
        (
            "au",
            True,
            "apac",
            [{"id": "RU", "direct": True}, {"id": "AU", "direct": True, "region": "APAC"}],
        ),
    ],
)
@pytest.mark.happy_path
def test_http_client_using_proper_regional_auth_endpoint(client, country, is_midpop, expected_region, countries):
    record = {"record_key": "key1", "version": 0}

    token_client = OAuthTokenClient(client_id="client_id", client_secret="client_secret", scope="test")
    client = HttpClient(env_id="test", token_client=token_client)

    httpretty.register_uri(
        httpretty.GET, HttpClient.DEFAULT_COUNTRIES_ENDPOINT, body=json.dumps({"countries": countries})
    )

    httpretty.register_uri(
        httpretty.GET,
        HttpClient.get_pop_url(country if is_midpop else HttpClient.DEFAULT_COUNTRY)
        + "/v2/storage/records/"
        + country
        + "/"
        + record.get("record_key"),
        body=json.dumps(record),
    )

    httpretty.register_uri(
        httpretty.POST,
        OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS[expected_region],
        responses=[
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
        ],
    )

    client.read.when.called_with(country=country, record_key=record.get("record_key")).should_not.throw(Exception)


@httpretty.activate
@pytest.mark.parametrize(
    "country,  expected_region",
    [("ca", "emea"), ("ru", "emea"), ("ag", "emea"), ("au", "emea")],
)
@pytest.mark.happy_path
def test_http_client_using_default_regional_auth_for_custom_endpoint(client, country, expected_region):
    record = {"record_key": "key1", "version": 0}

    token_client = OAuthTokenClient(client_id="client_id", client_secret="client_secret", scope="test")
    client = HttpClient(env_id="test", token_client=token_client, endpoint=POPAPI_URL)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + country + "/" + record.get("record_key"),
        body=json.dumps(record),
    )

    httpretty.register_uri(
        httpretty.POST,
        OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS[expected_region],
        responses=[
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
        ],
    )

    client.read.when.called_with(country=country, record_key=record.get("record_key")).should_not.throw(Exception)


@httpretty.activate
@pytest.mark.parametrize("country", ["ca", "ru", "ag", "au"])
@pytest.mark.parametrize("auth_endpoints", [{"default": "https://auth.io"}])
@pytest.mark.parametrize("endpoint", [POPAPI_URL])
@pytest.mark.happy_path
def test_http_client_using_custom_auth_endpoint_for_custom_endpoint(client, country, auth_endpoints, endpoint):
    record = {"record_key": "key1", "version": 0}

    token_client = OAuthTokenClient(
        client_id="client_id", client_secret="client_secret", scope="test", auth_endpoints=auth_endpoints
    )
    client = HttpClient(env_id="test", token_client=token_client, endpoint=endpoint)

    httpretty.register_uri(
        httpretty.GET,
        endpoint + "/v2/storage/records/" + country + "/" + record.get("record_key"),
        body=json.dumps(record),
    )

    httpretty.register_uri(
        httpretty.POST,
        auth_endpoints["default"],
        responses=[
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
        ],
    )

    client.read.when.called_with(country=country, record_key=record.get("record_key")).should_not.throw(Exception)


@httpretty.activate
@pytest.mark.parametrize(
    "country, is_midpop,  expected_region, countries",
    [
        (
            "ca",
            False,
            "emea",
            [{"id": "RU", "direct": True, "region": "EMEA"}, {"id": "AG", "direct": False}],
        ),
        (
            "ru",
            True,
            "emea",
            [{"id": "RU", "direct": True, "region": "EMEA"}, {"id": "AG", "direct": False}],
        ),
        (
            "ag",
            False,
            "default",
            [{"id": "RU", "direct": True}, {"id": "AG", "direct": False, "region": "AMER"}],
        ),
        (
            "ag",
            True,
            "default",
            [{"id": "RU", "direct": True}, {"id": "AG", "direct": True, "region": "AMER"}],
        ),
        (
            "au",
            False,
            "emea",
            [{"id": "RU", "direct": True}, {"id": "AU", "direct": False, "region": "APAC"}],
        ),
        (
            "au",
            True,
            "apac",
            [{"id": "RU", "direct": True}, {"id": "AU", "direct": True, "region": "APAC"}],
        ),
    ],
)
@pytest.mark.happy_path
def test_http_client_using_proper_regional_auth_endpoint_with_mask(
    client, country, is_midpop, expected_region, countries
):
    endpoint_mask = ".qa.incountry.com"
    record = {"record_key": "key1", "version": 0}

    token_client = OAuthTokenClient(
        client_id="client_id",
        client_secret="client_secret",
        scope="test",
    )
    client = HttpClient(
        env_id="test",
        token_client=token_client,
        endpoint_mask=endpoint_mask,
    )

    httpretty.register_uri(
        httpretty.GET, HttpClient.DEFAULT_COUNTRIES_ENDPOINT, body=json.dumps({"countries": countries})
    )

    pop_url = HttpClient.get_pop_url(country if is_midpop else HttpClient.DEFAULT_COUNTRY, endpoint_mask)

    httpretty.register_uri(
        httpretty.GET,
        pop_url + "/v2/storage/records/" + country + "/" + record.get("record_key"),
        body=json.dumps(record),
    )

    httpretty.register_uri(
        httpretty.POST,
        OAuthTokenClient.get_endpoint(expected_region),
        responses=[
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
        ],
    )

    client.read.when.called_with(country=country, record_key=record.get("record_key")).should_not.throw(Exception)


@httpretty.activate
@pytest.mark.parametrize(
    "country, is_midpop,  expected_region, countries",
    [
        (
            "ca",
            False,
            "default",
            [{"id": "RU", "direct": True, "region": "EMEA"}, {"id": "AG", "direct": False}],
        ),
        (
            "ru",
            True,
            "default",
            [{"id": "RU", "direct": True, "region": "EMEA"}, {"id": "AG", "direct": False}],
        ),
        (
            "ag",
            False,
            "default",
            [{"id": "RU", "direct": True}, {"id": "AG", "direct": False, "region": "AMER"}],
        ),
        (
            "ag",
            True,
            "default",
            [{"id": "RU", "direct": True}, {"id": "AG", "direct": True, "region": "AMER"}],
        ),
        (
            "au",
            False,
            "default",
            [{"id": "RU", "direct": True}, {"id": "AU", "direct": False, "region": "APAC"}],
        ),
        (
            "au",
            True,
            "default",
            [{"id": "RU", "direct": True}, {"id": "AU", "direct": True, "region": "APAC"}],
        ),
    ],
)
@pytest.mark.happy_path
def test_http_client_using_proper_regional_auth_endpoint_with_mask_and_custom_endpoint(
    client, country, is_midpop, expected_region, countries
):
    endpoint_mask = ".qa.incountry.com"
    record = {"record_key": "key1", "version": 0}

    token_client = OAuthTokenClient(
        client_id="client_id",
        client_secret="client_secret",
        scope="test",
    )
    client = HttpClient(
        env_id="test",
        token_client=token_client,
        endpoint=POPAPI_URL,
        endpoint_mask=endpoint_mask,
    )

    httpretty.register_uri(
        httpretty.GET, HttpClient.DEFAULT_COUNTRIES_ENDPOINT, body=json.dumps({"countries": countries})
    )

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + country + "/" + record.get("record_key"),
        body=json.dumps(record),
    )

    httpretty.register_uri(
        httpretty.POST,
        OAuthTokenClient.get_endpoint(expected_region),
        responses=[
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
        ],
    )

    client.read.when.called_with(country=country, record_key=record.get("record_key")).should_not.throw(Exception)


@httpretty.activate
@pytest.mark.parametrize("endpoint_mask", [None, ".private.incountry.com"])
@pytest.mark.parametrize(
    "auth_endpoints",
    [
        {
            "default": "https://auth1.com",
            "emea": "https://auth2.com",
            "amer": "https://auth3.com",
            "apac": "https://auth4.com",
        }
    ],
)
@pytest.mark.parametrize(
    "country, is_midpop, expected_region, countries",
    [
        (
            "ca",
            False,
            "default",
            [{"id": "RU", "direct": True, "region": "EMEA"}, {"id": "AG", "direct": False}],
        ),
        (
            "ru",
            True,
            "emea",
            [{"id": "RU", "direct": True, "region": "EMEA"}, {"id": "AG", "direct": False}],
        ),
        (
            "ag",
            False,
            "default",
            [{"id": "RU", "direct": True}, {"id": "AG", "direct": False, "region": "AMER"}],
        ),
        (
            "ag",
            True,
            "amer",
            [{"id": "RU", "direct": True}, {"id": "AG", "direct": True, "region": "AMER"}],
        ),
        (
            "au",
            False,
            "default",
            [{"id": "RU", "direct": True}, {"id": "AU", "direct": False, "region": "APAC"}],
        ),
        (
            "au",
            True,
            "apac",
            [{"id": "RU", "direct": True}, {"id": "AU", "direct": True, "region": "APAC"}],
        ),
    ],
)
@pytest.mark.happy_path
def test_http_client_using_custom_auth_endpoints(
    client, endpoint_mask, auth_endpoints, country, is_midpop, expected_region, countries
):
    record = {"record_key": "key1", "version": 0}

    token_client = OAuthTokenClient(
        client_id="client_id", client_secret="client_secret", scope="test", auth_endpoints=auth_endpoints
    )
    client = HttpClient(env_id="test", token_client=token_client, endpoint_mask=endpoint_mask)

    httpretty.register_uri(
        httpretty.GET, HttpClient.DEFAULT_COUNTRIES_ENDPOINT, body=json.dumps({"countries": countries})
    )

    httpretty.register_uri(
        httpretty.GET,
        HttpClient.get_pop_url(country if is_midpop else HttpClient.DEFAULT_COUNTRY, endpoint_mask=endpoint_mask)
        + "/v2/storage/records/"
        + country
        + "/"
        + record.get("record_key"),
        body=json.dumps(record),
    )

    httpretty.register_uri(
        httpretty.POST,
        auth_endpoints[expected_region],
        responses=[
            httpretty.Response(body=json.dumps({"access_token": str(uuid.uuid1()), "expires_in": 300}), status=200),
        ],
    )

    client.read.when.called_with(country=country, record_key=record.get("record_key")).should_not.throw(Exception)


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [get_attachment_meta_valid_response()],
)
@pytest.mark.parametrize("upsert", [True, False])
@pytest.mark.parametrize("mime_type", [None, "application/python"])
@pytest.mark.happy_path
def test_add_attachment_valid_response(client, response, upsert, mime_type):
    f = open(__file__, "rb")
    original_file_body = f.read()
    f.seek(0)

    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.PUT if upsert else httpretty.POST,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments",
        body=json.dumps(response, default=json_converter),
    )

    res = client().add_attachment(
        country=COUNTRY, record_key=record_key_hash, upsert=upsert, file=f, mime_type=mime_type
    )
    res_json = json.dumps(res, default=json_converter)
    res_json.should.contain(json.dumps(response, default=json_converter))

    last_request = httpretty.last_request()

    decoder = MultipartDecoder(last_request.body, last_request.headers["Content-Type"])
    assert decoder.parts[0].content == original_file_body
    if mime_type is not None:
        assert decoder.parts[0].headers[b"Content-Type"] == mime_type.encode("utf-8")


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    get_attachment_meta_invalid_responses(),
)
@pytest.mark.parametrize("upsert", [True, False])
@pytest.mark.happy_path
def test_add_attachment_invalid_response(client, response, upsert):
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.PUT if upsert else httpretty.POST,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments",
        body=json.dumps(response, default=json_converter),
    )

    client().add_attachment.when.called_with(
        country=COUNTRY, record_key=record_key_hash, upsert=upsert, file=open(__file__, "rb")
    ).should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [{}, [], (), True, False, "", 123, "123"],
)
@pytest.mark.parametrize("upsert", [True, False])
@pytest.mark.happy_path
def test_add_attachment_invalid_response_2(client, response, upsert):
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.PUT if upsert else httpretty.POST,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments",
        body=json.dumps(response, default=json_converter),
    )

    client().add_attachment.when.called_with(
        country=COUNTRY, record_key=record_key_hash, upsert=upsert, file=open(__file__, "rb")
    ).should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [get_attachment_meta_valid_response()],
)
@pytest.mark.parametrize(
    "mime_type",
    ["application/octet-stream", "text/plain", "application/json"],
)
@pytest.mark.happy_path
def test_get_attachment_valid_response(client, response, mime_type):
    f = open(__file__, "rb")
    original_file_body = f.read()
    f.seek(0)

    filename = os.path.basename(__file__)
    file_id = get_random_str()
    record_key_hash = get_key_hash(str(uuid.uuid1()))

    httpretty.register_uri(
        httpretty.GET,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}",
        body=original_file_body,
        content_type=mime_type,
        content_disposition=f"attachment; filename*=UTF-8''{filename}",
    )

    res = client().get_attachment_file(country=COUNTRY, record_key=record_key_hash, file_id=file_id)

    assert res["filename"] == filename
    assert res["file"].read() == original_file_body


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [get_attachment_meta_valid_response()],
)
@pytest.mark.parametrize(
    "mime_type",
    ["application/octet-stream", "text/plain", "application/json"],
)
@pytest.mark.happy_path
def test_get_attachment_without_filename(client, response, mime_type):
    f = open(__file__, "rb")
    original_file_body = f.read()
    f.seek(0)

    file_id = get_random_str()
    record_key_hash = get_key_hash(str(uuid.uuid1()))

    httpretty.register_uri(
        httpretty.GET,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}",
        body=original_file_body,
        content_type=mime_type,
    )

    res = client().get_attachment_file(country=COUNTRY, record_key=record_key_hash, file_id=file_id)

    assert res["file"].read() == original_file_body
    assert res["filename"] == "file"


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [get_attachment_meta_valid_response()],
)
@pytest.mark.happy_path
def test_get_attachment_meta_valid_response(client, response):
    file_id = get_random_str()
    record_key = get_key_hash(str(uuid.uuid1()))

    httpretty.register_uri(
        httpretty.GET,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key}/attachments/{file_id}/meta",
        body=json.dumps(response, default=json_converter),
    )

    res = client().get_attachment_meta(country=COUNTRY, record_key=record_key, file_id=file_id)
    res_json = json.dumps(res, default=json_converter)
    res_json.should.contain(json.dumps(response, default=json_converter))


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    get_attachment_meta_invalid_responses(),
)
@pytest.mark.happy_path
def test_get_attachment_meta_invalid_response(client, response):
    file_id = get_random_str()
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}/meta",
        body=json.dumps(response, default=json_converter),
    )

    client().get_attachment_meta.when.called_with(
        country=COUNTRY, record_key=record_key_hash, file_id=file_id
    ).should.throw(StorageServerException)


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
@pytest.mark.happy_path
def test_update_attachment_meta_valid_response(client, new_meta, response):
    file_id = get_random_str()
    record_key = get_key_hash(str(uuid.uuid1()))

    httpretty.register_uri(
        httpretty.PATCH,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key}/attachments/{file_id}/meta",
        body=json.dumps(response, default=json_converter),
    )

    res = client().update_attachment_meta(country=COUNTRY, record_key=record_key, file_id=file_id, meta=new_meta)
    res_json = json.dumps(res, default=json_converter)
    res_json.should.contain(json.dumps(response, default=json_converter))

    last_request = httpretty.last_request()
    last_request.parsed_body.should.equal(new_meta)


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    get_attachment_meta_invalid_responses(),
)
@pytest.mark.happy_path
def test_update_attachment_meta_invalid_response(client, response):
    file_id = get_random_str()
    record_key = str(uuid.uuid1())
    record_key_hash = get_key_hash(record_key)

    httpretty.register_uri(
        httpretty.GET,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key_hash}/attachments/{file_id}/meta",
        body=json.dumps(response, default=json_converter),
    )

    client().get_attachment_meta.when.called_with(
        country=COUNTRY, record_key=record_key_hash, file_id=file_id
    ).should.throw(StorageServerException)


@httpretty.activate
@pytest.mark.parametrize(
    "response",
    ["", [], {}],
)
@pytest.mark.happy_path
def test_delete_attachment_meta_valid_response(client, response):
    file_id = get_random_str()
    record_key = get_key_hash(str(uuid.uuid1()))

    httpretty.register_uri(
        httpretty.DELETE,
        f"{POPAPI_URL}/v2/storage/records/{COUNTRY}/{record_key}/attachments/{file_id}",
        body=json.dumps(response),
    )

    res = client().delete_attachment(country=COUNTRY, record_key=record_key, file_id=file_id)
    assert res == response
