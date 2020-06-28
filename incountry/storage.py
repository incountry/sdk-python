from __future__ import absolute_import
from typing import List, Dict, Union, Any

from .incountry_crypto import InCrypto
from .crypto_utils import decrypt_record, encrypt_record, get_salted_hash, HASHABLE_KEYS, normalize_key
from .exceptions import StorageCryptoException
from .validation import validate_model, validate_encryption_enabled
from .http_client import HttpClient
from .models import Country, FindFilter, FindFilterOperators, Record, RecordListForBatch, StorageWithEnv
from .token_clients import ApiKeyTokenClient, OAuthTokenClient


class Storage:
    @validate_model(StorageWithEnv)
    def __init__(
        self,
        environment_id: str = None,
        api_key: str = None,
        client_id: str = None,
        client_secret: str = None,
        endpoint: str = None,
        encrypt: bool = True,
        secret_key_accessor=None,
        custom_encryption_configs=None,
        debug: bool = False,
        options: Dict[str, Any] = {},
    ):
        """
        Returns a client to talk to the InCountry storage network.

        To find the storage endpoint, we use this logic:

        - Attempt to connect to <country>.api.incountry.io
        - If that fails, then fall back to us.api.incountry.io which
            will forward data to miniPOPs

        @param environment_id: The id of the environment into which you wll store data
        @param api_key: Your API key
        @param endpoint: Optional. Will use DNS routing by default.
        @param encrypt: Pass True (default) to encrypt values before storing
        @param secret_key_accessor: pass SecretKeyAccessor class instance which provides secret key for encrytion
        @param debug: pass True to enable some debug logging

        You can set parameters via env vars also:

        INC_ENVIRONMENT_ID
        INC_API_KEY
        INC_ENDPOINT
        """

        self.debug = debug
        self.env_id = environment_id
        self.encrypt = encrypt
        self.normalize_keys = options.get("normalize_keys", False)
        self.crypto = InCrypto(secret_key_accessor, custom_encryption_configs) if self.encrypt else InCrypto()

        token_client = (
            ApiKeyTokenClient(api_key=api_key)
            if api_key is not None
            else OAuthTokenClient(
                client_id=client_id,
                client_secret=client_secret,
                scope=self.env_id,
                auth_endpoints=options.get("auth_endpoints"),
                options=options.get("http_options", {}),
            )
        )
        self.http_client = HttpClient(
            env_id=self.env_id,
            token_client=token_client,
            endpoint=endpoint,
            debug=self.debug,
            endpoint_mask=options.get("endpoint_mask", None),
            countries_endpoint=options.get("countries_endpoint", None),
            options=options.get("http_options", {}),
        )

        self.log("Using API key: ", api_key)

    @validate_model(Country)
    @validate_model(Record)
    def write(
        self,
        country: str,
        key: str,
        body: str = None,
        key2: str = None,
        key3: str = None,
        profile_key: str = None,
        range_key: int = None,
    ) -> Dict[str, Dict]:
        record = {}
        for k in ["key", "body", "key2", "key3", "profile_key", "range_key"]:
            if locals().get(k, None):
                record[k] = locals().get(k, None)

        data_to_send = self.encrypt_record(record)
        self.http_client.write(country=country, data=data_to_send)
        return {"record": record}

    @validate_model(Country)
    @validate_model(RecordListForBatch)
    def batch_write(self, country: str, records: list) -> Dict[str, List]:
        encrypted_records = [self.encrypt_record(record) for record in records]
        data_to_send = {"records": encrypted_records}
        self.http_client.batch_write(country=country, data=data_to_send)
        return {"records": records}

    @validate_model(Country)
    @validate_model(Record)
    def read(self, country: str, key: str) -> Dict[str, Dict]:
        key = get_salted_hash(self.normalize_key(key), self.env_id)
        response = self.http_client.read(country=country, key=key)
        return {"record": self.decrypt_record(response)}

    @validate_model(Country)
    @validate_model(FindFilter)
    def find(
        self,
        country: str,
        limit: int = None,
        offset: int = None,
        key: Union[str, List[str], Dict] = None,
        key2: Union[str, List[str], Dict] = None,
        key3: Union[str, List[str], Dict] = None,
        profile_key: Union[str, List[str], Dict] = None,
        range_key: Union[int, List[int], Dict] = None,
        version: Union[int, List[int], Dict] = None,
    ) -> Dict[str, Any]:
        filter_params = self.prepare_filter_params(
            key=key, key2=key2, key3=key3, profile_key=profile_key, range_key=range_key, version=version,
        )
        options = {"limit": limit, "offset": offset}

        response = self.http_client.find(country=country, data={"filter": filter_params, "options": options})

        decoded_records = []
        undecoded_records = []
        for record in response["data"]:
            try:
                decoded_records.append(self.decrypt_record(record))
            except StorageCryptoException as error:
                undecoded_records.append({"rawData": record, "error": error})

        result = {
            "meta": response["meta"],
            "records": decoded_records,
        }
        if len(undecoded_records) > 0:
            result["errors"] = undecoded_records

        return result

    @validate_model(Country)
    @validate_model(FindFilter)
    def find_one(
        self,
        country: str,
        offset: int = None,
        key: Union[str, List[str], Dict] = None,
        key2: Union[str, List[str], Dict] = None,
        key3: Union[str, List[str], Dict] = None,
        profile_key: Union[str, List[str], Dict] = None,
        range_key: Union[int, List[int], Dict] = None,
        version: Union[int, List[int], Dict] = None,
    ) -> Union[None, Dict[str, Dict]]:
        result = self.find(
            country=country,
            limit=1,
            offset=offset,
            key=key,
            key2=key2,
            key3=key3,
            profile_key=profile_key,
            range_key=range_key,
            version=version,
        )
        return {"record": result["records"][0]} if len(result["records"]) else None

    @validate_model(Country)
    @validate_model(Record)
    def delete(self, country: str, key: str) -> Dict[str, bool]:
        key = get_salted_hash(self.normalize_key(key), self.env_id)
        self.http_client.delete(country=country, key=key)
        return {"success": True}

    @validate_encryption_enabled
    @validate_model(Country)
    @validate_model(FindFilter)
    def migrate(self, country: str, limit: int = None) -> Dict[str, int]:
        current_secret_version = self.crypto.get_current_secret_version()
        find_res = self.find(country=country, limit=limit, version={"$not": current_secret_version})
        self.batch_write(country=country, records=find_res["records"])

        return {
            "migrated": find_res["meta"]["count"],
            "total_left": find_res["meta"]["total"] - find_res["meta"]["count"],
        }

    ###########################################
    # Common functions
    ###########################################
    def log(self, *args):
        if self.debug:
            print("[incountry] ", args)

    def prepare_filter_string_param(self, value):
        if isinstance(value, list):
            return [get_salted_hash(self.normalize_key(x), self.env_id) for x in value]
        return get_salted_hash(self.normalize_key(value), self.env_id)

    def prepare_filter_params(self, **filter_kwargs):
        filter_params = {}
        for k in HASHABLE_KEYS:
            filter_value = filter_kwargs.get(k, None)
            if filter_value is None:
                continue
            if FindFilterOperators.NOT in filter_value:
                filter_params[k] = {}
                filter_params[k][FindFilterOperators.NOT] = self.prepare_filter_string_param(
                    filter_value[FindFilterOperators.NOT]
                )
            else:
                filter_params[k] = self.prepare_filter_string_param(filter_value)
        if filter_kwargs.get("range_key", None):
            filter_params["range_key"] = filter_kwargs["range_key"]
        return filter_params

    def encrypt_record(self, record):
        return encrypt_record(self.crypto, record, self.env_id, self.normalize_keys)

    def decrypt_record(self, record):
        return decrypt_record(self.crypto, record)

    def normalize_key(self, key):
        return normalize_key(key, self.normalize_keys)
