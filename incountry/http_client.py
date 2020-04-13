from __future__ import absolute_import

import requests
import json

from .exceptions import StorageServerError
from .models import HttpRecordWrite, HttpRecordBatchWrite, HttpRecordRead, HttpRecordFind, HttpRecordDelete
from .validation import validate_http_response
from .__version__ import __version__


class HttpClient:
    PORTALBACKEND_URI = "https://portal-backend.incountry.com"
    DEFAULT_ENDPOINT = "https://us.api.incountry.io"

    def __init__(self, env_id, api_key, endpoint=None, debug=False):
        self.api_key = api_key
        self.endpoint = endpoint
        self.env_id = env_id
        self.debug = debug

        if self.endpoint is None:
            self.log(f"Connecting to default endpoint: https://<country>.api.incountry.io")
        else:
            self.log(f"Connecting to custom endpoint: {self.endpoint}")

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

    def request(self, country, path="", method="GET", data=None):
        try:
            endpoint = self.getendpoint(country, "/v2/storage/records/" + country + path)
            res = requests.request(method=method, url=endpoint, headers=self.get_headers(), data=data)

            if res.status_code >= 400:
                raise StorageServerError("{} {} - {}".format(res.status_code, res.url, res.text))

            try:
                return res.json()
            except Exception:
                return res.text
        except Exception as e:
            raise StorageServerError(e) from None

    def get_midpop_country_codes(self):
        r = requests.get(self.PORTALBACKEND_URI + "/countries")
        if r.status_code >= 400:
            raise StorageServerError("Unable to retrieve countries list")
        data = r.json()

        return [country["id"].lower() for country in data["countries"] if country["direct"]]

    def getendpoint(self, country, path):
        if not path.startswith("/"):
            path = "/" + path

        if self.endpoint:
            res = "{}{}".format(self.endpoint, path)
            self.log("Endpoint: ", res)
            return res

        midpops = self.get_midpop_country_codes()

        is_midpop = country in midpops

        res = HttpClient.get_midpop_url(country) + path if is_midpop else "{}{}".format(self.DEFAULT_ENDPOINT, path)

        self.log("Endpoint: ", res)
        return res

    def get_headers(self):
        return {
            "Authorization": "Bearer " + self.api_key,
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
