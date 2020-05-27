from __future__ import absolute_import

import requests
import json

from .exceptions import StorageServerException
from .models import HttpOptions, HttpRecordWrite, HttpRecordBatchWrite, HttpRecordRead, HttpRecordFind, HttpRecordDelete
from .validation import validate_http_response
from .__version__ import __version__


class HttpClient:
    PORTALBACKEND_URI = "https://portal-backend.incountry.com"
    DEFAULT_HOST = "https://us.api.incountry.io"
    AUTH_TOTAL_RETRIES = 1

    def __init__(self, env_id, token_client, host=None, debug=False, options={}):
        self.token_client = token_client
        self.host = host
        self.env_id = env_id
        self.debug = debug
        self.options = HttpOptions(**options)

        if self.host is None:
            self.log(
                f"Connecting to default host: https://<country>.api.incountry.io. "
                f"Connection timeout {self.options.timeout}s"
            )
        else:
            self.log(f"Connecting to custom host: {self.host}. Connection timeout {self.options.timeout}s")

    @validate_http_response(HttpRecordWrite)
    def write(self, country, data):
        response = self.request(country, method="POST", data=json.dumps(data))
        return response

    @validate_http_response(HttpRecordBatchWrite)
    def batch_write(self, country, data):
        response = self.request(country, path="/batchWrite", method="POST", data=json.dumps(data))
        return response

    @validate_http_response(HttpRecordRead)
    def read(self, country, key):
        response = self.request(country, path="/" + key)
        return response

    @validate_http_response(HttpRecordFind)
    def find(self, country, data):
        response = self.request(country, path="/find", method="POST", data=json.dumps(data))
        return response

    @validate_http_response(HttpRecordDelete)
    def delete(self, country, key):
        return self.request(country, path="/" + key, method="DELETE")

    def request(self, country, path="", method="GET", data=None, retries=AUTH_TOTAL_RETRIES):
        try:
            host = self.get_pop_host(country)
            url = self.get_request_url(host, "/v2/storage/records/", country, path)
            auth_token = self.token_client.get_token(host=host, refetch=retries < HttpClient.AUTH_TOTAL_RETRIES)

            res = requests.request(
                method=method,
                url=url,
                headers=self.get_headers(auth_token=auth_token),
                data=data,
                timeout=self.options.timeout,
            )

            if res.status_code == 401 and self.token_client.can_refetch() and retries > 0:
                return self.request(country=country, path=path, method=method, data=data, retries=retries - 1)

            if res.status_code >= 400:
                raise StorageServerException("{} {} - {}".format(res.status_code, res.url, res.text))

            try:
                return res.json()
            except Exception:
                return res.text
        except StorageServerException as e:
            raise e
        except Exception as e:
            raise StorageServerException(e)

    def get_midpop_country_codes(self):
        r = requests.get(self.PORTALBACKEND_URI + "/countries", timeout=self.options.timeout)
        if r.status_code >= 400:
            raise StorageServerException("Unable to retrieve countries list")
        data = r.json()

        return [country["id"].lower() for country in data["countries"] if country["direct"]]

    def get_pop_host(self, country):
        if self.host:
            return self.host

        midpops = self.get_midpop_country_codes()
        is_midpop = country in midpops

        return HttpClient.get_midpop_url(country) if is_midpop else self.DEFAULT_HOST

    def get_request_url(self, host, *parts):
        res_url = host.rstrip("/")
        for part in parts:
            res_url += "/" + part.strip("/")
        return res_url.strip("/")

    def get_headers(self, auth_token):
        return {
            "Authorization": "Bearer " + auth_token,
            "x-env-id": self.env_id,
            "Content-Type": "application/json",
            "User-Agent": "SDK-Python/" + __version__,
        }

    def log(self, *args):
        if self.debug:
            print("[incountry] ", args)

    @staticmethod
    def get_midpop_url(country):
        return "https://{}.api.incountry.io".format(country)
