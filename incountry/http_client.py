from __future__ import absolute_import

import requests
import json

from .exceptions import StorageServerException
from .models import HttpOptions, HttpRecordRead, HttpRecordFind
from .validation import validate_http_response
from .__version__ import __version__


class HttpClient:
    DEFAULT_COUNTRIES_ENDPOINT = "https://portal-backend.incountry.com/countries"
    DEFAULT_COUNTRY = "us"
    DEFAULT_ENDPOINT_MASK = "-mt-01.api.incountry.io"
    AUTH_TOTAL_RETRIES = 1

    DEFAULT_AUTH_REGION = "default"

    def __init__(
        self, env_id, token_client, endpoint=None, debug=False, endpoint_mask=None, countries_endpoint=None, options={},
    ):
        self.token_client = token_client
        self.endpoint = endpoint
        self.env_id = env_id
        self.debug = debug
        self.endpoint_mask = endpoint_mask
        self.options = HttpOptions(**options)
        self.countries_endpoint = countries_endpoint or HttpClient.DEFAULT_COUNTRIES_ENDPOINT

        if self.endpoint is None:
            self.log(
                f"Connecting to default endpoint: "
                f"https://<country>.{self.endpoint_mask or HttpClient.DEFAULT_ENDPOINT_MASK}. "
                f"Connection timeout {self.options.timeout}s"
            )
        else:
            self.log(f"Connecting to custom endpoint: {self.endpoint}. Connection timeout {self.options.timeout}s")

    def write(self, country, data):
        response = self.request(country, method="POST", data=json.dumps(data))
        return response

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

    def delete(self, country, key):
        return self.request(country, path="/" + key, method="DELETE")

    def request(self, country, path="", method="GET", data=None, retries=AUTH_TOTAL_RETRIES):
        try:
            (endpoint, audience, region) = self.get_request_pop_details(country)

            url = self.get_request_url(endpoint, "/v2/storage/records/", country, path)
            auth_token = self.token_client.get_token(
                audience=audience, region=region, refetch=retries < HttpClient.AUTH_TOTAL_RETRIES
            )

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

    def get_country_details(self, country):
        r = requests.get(self.countries_endpoint, timeout=self.options.timeout)
        if r.status_code >= 400:
            raise StorageServerException("Unable to retrieve countries list")
        countries_data = r.json()["countries"]

        country_data = next((data for data in countries_data if data["id"].lower() == country), None,)

        if country_data is None:
            return (False, HttpClient.DEFAULT_AUTH_REGION)

        return (country_data.get("direct", False) is True, country_data.get("region", "").lower())

    def get_request_pop_details(self, country):
        if self.endpoint and self.endpoint_mask is None:
            return (self.endpoint, self.endpoint, HttpClient.DEFAULT_AUTH_REGION)

        endpoint_mask_to_use = self.endpoint_mask or HttpClient.DEFAULT_ENDPOINT_MASK

        region = HttpClient.DEFAULT_AUTH_REGION
        endpoint = HttpClient.get_pop_url(HttpClient.DEFAULT_COUNTRY, HttpClient.DEFAULT_ENDPOINT_MASK)
        country_endpoint = HttpClient.get_pop_url(country, endpoint_mask_to_use)
        audience = endpoint

        if self.endpoint:
            endpoint = self.endpoint
            audience = endpoint if endpoint == country_endpoint else f"{endpoint} {country_endpoint}"
        else:
            (is_midpop, pop_region) = self.get_country_details(country)

            if is_midpop:
                endpoint = country_endpoint
                audience = endpoint
                region = pop_region
            else:
                endpoint = HttpClient.get_pop_url(HttpClient.DEFAULT_COUNTRY, endpoint_mask_to_use)
                audience = f"{endpoint} {country_endpoint}"

        return (endpoint, audience, region)

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
    def get_pop_url(country, endpoint_mask=DEFAULT_ENDPOINT_MASK):
        endpoint_mask = endpoint_mask or HttpClient.DEFAULT_ENDPOINT_MASK
        return f"https://{country}{endpoint_mask}"
