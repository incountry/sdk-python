from __future__ import absolute_import

import requests
import re
from io import BytesIO
from pathlib import Path

from .exceptions import StorageServerException
from .models import HttpOptions, HttpRecordRead, HttpRecordFind, HttpAttachmentMeta
from .validation import validate_http_response
from .__version__ import __version__


class HttpClient:
    DEFAULT_COUNTRIES_ENDPOINT = "https://portal-backend.incountry.com/countries"
    DEFAULT_COUNTRY = "us"
    DEFAULT_ENDPOINT_MASK = "-mt-01.api.incountry.io"
    AUTH_TOTAL_RETRIES = 1

    DEFAULT_AUTH_REGION = "default"

    def __init__(
        self,
        env_id,
        token_client,
        endpoint=None,
        debug=False,
        endpoint_mask=None,
        countries_endpoint=None,
        options={},
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
        return self.request(country, method="POST", data=data)

    def batch_write(self, country, data):
        return self.request(country, path="/batchWrite", method="POST", data=data)

    @validate_http_response(HttpRecordRead)
    def read(self, country, record_key):
        return self.request(country, path=f"/{record_key}")

    @validate_http_response(HttpRecordFind)
    def find(self, country, data):
        return self.request(country, path="/find", method="POST", data=data)

    def delete(self, country, record_key):
        return self.request(country, path=f"/{record_key}", method="DELETE")

    @validate_http_response(HttpAttachmentMeta)
    def add_attachment(self, country, record_key, file, upsert=False, mime_type=None):
        filename = Path(getattr(file, "name", "file")).name
        files = {"file": file}

        if mime_type is not None:
            files["file"] = (filename, file, mime_type)

        return self.request(
            country,
            path=f"/{record_key}/attachments",
            method="PUT" if upsert else "POST",
            files=files,
        )

    def delete_attachment(self, country, record_key, file_id):
        return self.request(country, path=f"/{record_key}/attachments/{file_id}", method="DELETE")

    def get_attachment_file(self, country, record_key, file_id):
        response = self.request(country, path=f"/{record_key}/attachments/{file_id}", method="GET", raw=True)
        return {"filename": self.get_filename_from_headers(response.headers), "file": BytesIO(response.content)}

    @validate_http_response(HttpAttachmentMeta)
    def get_attachment_meta(self, country, record_key, file_id):
        return self.request(country, path=f"/{record_key}/attachments/{file_id}/meta", method="GET")

    @validate_http_response(HttpAttachmentMeta)
    def update_attachment_meta(self, country, record_key, file_id, meta):
        return self.request(country, path=f"/{record_key}/attachments/{file_id}/meta", method="PATCH", data=meta)

    def request(
        self,
        country,
        path="",
        method="GET",
        data=None,
        retries=AUTH_TOTAL_RETRIES,
        files=None,
        raw=False,
    ):
        try:
            (endpoint, audience, region) = self.get_request_pop_details(country)

            url = self.get_request_url(endpoint, "/v2/storage/records/", country, path)
            auth_token = self.token_client.get_token(
                audience=audience, region=region, refetch=retries < HttpClient.AUTH_TOTAL_RETRIES
            )

            params = {
                "method": method,
                "url": url,
                "headers": self.get_headers(auth_token=auth_token),
                "timeout": self.options.timeout,
            }

            if data is not None:
                params["json"] = data
            if files is not None:
                params["files"] = files

            with requests.request(**params) as res:
                if res.status_code == 401 and self.token_client.can_refetch() and retries > 0:
                    return self.request(country=country, path=path, method=method, data=data, retries=retries - 1)

                if res.status_code >= 400:
                    raise StorageServerException(f"{res.request.method} {res.status_code} {res.url} - {res.text}")

                try:
                    if raw:
                        return res
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

        country_data = next(
            (data for data in countries_data if data["id"].lower() == country),
            None,
        )

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
            "User-Agent": "SDK-Python/" + __version__,
        }

    def get_filename_from_headers(self, headers):
        content_disposition = headers.get("content-disposition", None)
        if content_disposition is None:
            return "file"
        filename_re_from_header = re.findall("filename\\*=UTF-8''([^;]*)", headers["content-disposition"])
        if len(filename_re_from_header) == 0:
            return "file"
        return requests.utils.unquote(filename_re_from_header[0].strip('"'))

    def log(self, *args):
        if self.debug:
            print("[incountry] ", args)

    @staticmethod
    def get_pop_url(country, endpoint_mask=DEFAULT_ENDPOINT_MASK):
        endpoint_mask = endpoint_mask or HttpClient.DEFAULT_ENDPOINT_MASK
        return f"https://{country}{endpoint_mask}"
