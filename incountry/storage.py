from __future__ import absolute_import
from typing import List, Dict, Union, Any, Optional, BinaryIO
from datetime import datetime

from .crypto_utils import (
    hash_object_record_keys,
    decrypt_record,
    encrypt_record,
    get_salted_hash,
    normalize_key,
    sanitize_obj_for_model,
)
from .exceptions import StorageCryptoException
from .incountry_crypto import InCrypto
from .http_client import HttpClient
from .models import (
    AttachmentCreate,
    AttachmentMetaUpdate,
    AttachmentRequest,
    Country,
    FindFilter,
    FIND_LIMIT,
    Record,
    RecordNonHashed,
    RecordListForBatch,
    StorageWithEnv,
    StorageOptions,
)
from .secret_key_accessor import SecretKeyAccessor
from .token_clients import ApiKeyTokenClient, OAuthTokenClient
from .types import TIntFilter, TStringFilter, TRecord
from .validation import validate_model, validate_encryption_enabled


class Storage:
    @validate_model(StorageWithEnv, exclude_to_dict={"options"})
    def __init__(
        self,
        environment_id: Optional[str] = None,
        api_key: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        endpoint: Optional[str] = None,
        encrypt: Optional[bool] = True,
        secret_key_accessor: Optional[SecretKeyAccessor] = None,
        custom_encryption_configs: Optional[List[dict]] = None,
        debug: Optional[bool] = False,
        options: Optional[Dict[str, Any]] = {},
    ):
        """Returns a client to talk to the InCountry storage network.

        Args:
            environment_id:
                The id of the environment you want to store records in. Defaults to None.
                Can also be set via INC_ENVIRONMENT_ID environment variable.
            api_key:
                Your API key. Defaults to None.
                Can also be set via INC_API_KEY environment variable.
            client_id:
                Client Id used for oAuth authorization. Defaults to None.
                Can also be set via INC_CLIENT_ID environment variable.
            client_secret:
                Client Secret used for oAuth authorization. Defaults to None.
                Can also be set via INC_CLIENT_SECRET environment variable.
            endpoint:
                Custom storage server endpoint to use. Defaults to None.
                Can also be set via INC_ENDPOINT environment variable.
            encrypt:
                Whether to encrypt data before storing in InCountry. Defaults to True.
            secret_key_accessor:
                SecretKeyAccessor class instance which provides encryption keys details. Defaults to None.
            custom_encryption_configs:
                List of custom encryption configurations. Defaults to None.
            debug:
                Pass True to enable some debug logging. Defaults to False.
            options:
                Options dict to tweak various Storage instance aspects. Defaults to {}.

        Raises:
            StorageClientException: in case constructor param validation fails,
            StorageCryptoException: in case any encryption-related error occurs.
            StorageException: in any other cases
        """

        self.debug = debug
        self.env_id = environment_id
        self.encrypt = encrypt
        self.options = StorageOptions(**options)
        self.crypto = InCrypto(secret_key_accessor, custom_encryption_configs) if self.encrypt else InCrypto()

        token_client = (
            ApiKeyTokenClient(api_key=api_key)
            if api_key is not None
            else OAuthTokenClient(
                client_id=client_id,
                client_secret=client_secret,
                scope=self.env_id,
                auth_endpoints=self.options.auth_endpoints,
                options=self.options.http_options,
            )
        )
        self.http_client = HttpClient(
            env_id=self.env_id,
            token_client=token_client,
            endpoint=endpoint,
            debug=self.debug,
            endpoint_mask=self.options.endpoint_mask,
            countries_endpoint=self.options.countries_endpoint,
            options=self.options.http_options,
        )

        self.log("Using API key: ", api_key)

    @validate_model(Country)
    @validate_model(
        {
            "condition": ("options", "hash_search_keys"),
            "values": [
                {"value": True, "model": Record},
                {"value": False, "model": RecordNonHashed},
            ],
        }
    )
    def write(self, country: str, record_key: str, **record_data: Union[str, int]) -> Dict[str, TRecord]:
        """Writes record to InCountry storage network.

        Args:
            country: Country to write record to
            record_key: Record primary key/identifier
            **record_data: Various record attributes.
                Available String attributes:
                - body, precommit_body, profile_key, service_key1, service_key2, key1, ..., key10.
                Available Int attributes:
                - range_key1, ..., range_key10

        Returns:
            Dict[str, TRecord]:
                A dict with record data you just wrote {"record": {"record_key": record_key, **record}}

        Raises:
            StorageClientException: in case method param validation fails.
            StorageServerException: in case InCountry server (either storage server or auth server) responds with error.
            StorageCryptoException: in case any encryption-related error occurs.
            StorageException: in any other cases.
        """

        record = sanitize_obj_for_model({"record_key": record_key, **record_data}, Record)

        data_to_send = self.encrypt_record(record)
        self.http_client.write(country=country, data=data_to_send)
        return {"record": record}

    @validate_model(Country)
    @validate_model(RecordListForBatch)
    def batch_write(self, country: str, records: List[TRecord]) -> Dict[str, List[TRecord]]:
        """Writes multiple records to InCountry storage network.

        Args:
            country: Country to write records to
            records: List of records. See Storage.write() for details on record attributes

        Returns:
            Dict[str, List[TRecord]]:
                A dict with record data you just wrote {"record": {"record_key": record_key, **record}}

        Raises:
            StorageClientException: in case method param validation fails.
            StorageServerException: in case InCountry server (either storage server or auth server) responds with error.
            StorageCryptoException: in case any encryption-related error occurs.
            StorageException: in any other cases.
        """

        encrypted_records = [self.encrypt_record(record) for record in records]
        data_to_send = {"records": encrypted_records}
        self.http_client.batch_write(country=country, data=data_to_send)
        return {"records": records}

    @validate_model(Country)
    @validate_model(Record)
    def read(self, country: str, record_key: str) -> Dict[str, TRecord]:
        """Reads record for the given record_key

        Args:
            country: Country to search record in
            record_key: Record primary key/identifier

        Returns:
            Dict[str, TRecord]:
                A dict with record data {"record": TRecord}

        Raises:
            StorageClientException: in case method param validation fails.
            StorageServerException: in case InCountry server (either storage server or auth server) responds with error
                (e.g. if record does not exist for the given record_key).
            StorageCryptoException: in case any encryption-related error occurs.
            StorageException: in any other cases.
        """
        record_key = get_salted_hash(self.normalize_key(record_key), self.env_id)
        response = self.http_client.read(country=country, record_key=record_key)
        return {"record": self.decrypt_record(response)}

    @validate_model(Country)
    @validate_model(FindFilter)
    def find(
        self,
        country: str,
        limit: Optional[int] = FIND_LIMIT,
        offset: Optional[int] = 0,
        **filters: Union[TIntFilter, TStringFilter],
    ) -> Dict[str, Any]:
        """Finds records that satisfy provided filters

        Args:
            country: Country to search records in
            limit: Maximum amount of records to be returned. Max limit is 100. Defaults to 100.
            offset: Search offset. Should be non-negative int. Defaults to 0.
            **filters: Various filters to tweak the search query.
                Available String filter keys:
                - profile_key, service_key1, service_key2, key1, ..., key10.
                Available String filter types:
                - single value: Storage.find(..., key1="v1"),
                - list of values: Storage.find(..., key1=["v1", "v2"]),
                - with $not operator: Storage.find(..., key1={"$not": "v1"}, key2={"$not":["v1", "v2"]}).

                Available Int filter keys:
                - version, range_key1, ..., range_key10.
                Available Int filter types:
                - single value: Storage.find(..., range_key1=1),
                - list of values: Storage.find(..., range_key1=[1, 2]),
                - with $not operator: Storage.find(..., range_key1={"$not": 1}, range_key2={"$not":[1, 2]}),
                - with $gt operator: Storage.find(..., range_key1={"$gt": 1}),
                - with $gte operator: Storage.find(..., range_key1={"$gte": 1}),
                - with $lt operator: Storage.find(..., range_key1={"$lt": 1}),
                - with $lte operator: Storage.find(..., range_key1={"$lte": 1}),
                - with comparison operators combination: Storage.find(..., range_key1={"$gt": 1, $lte": 10}),

        Returns:
            Dict[str, Any]:
                Found records with some meta information and errors data (if any) as dict:
                    {
                        "meta": {
                            "count": int,
                            "limit": int,
                            "offset": int,
                            "total": int,
                        },
                        "records": List[TRecord],
                        "errors": List,
                    }

                In case of any error occurs during records decryption, method will not raise StorageCryptoException
                but rather add raw record and the exception itself to "errors" list in reponse dict
                ({"errors": [..., {"rawData": TRecord, "error": StorageCryptoException}]})

        Raises:
            StorageClientException: in case method param validation fails.
            StorageServerException: in case InCountry server (either storage server or auth server) responds with error.
            StorageException: in any other cases.
        """

        filter_params = hash_object_record_keys(
            sanitize_obj_for_model(filters, FindFilter),
            self.env_id,
            normalize_keys=self.options.normalize_keys,
            hash_search_keys=self.options.hash_search_keys,
            hash_for_find=True,
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
        offset: Optional[int] = 0,
        **filters: Union[TIntFilter, TStringFilter],
    ) -> Union[None, Dict[str, Dict]]:
        """Finds record that satisfies provided filters

        Args:
            country: Country to search record in
            offset: Search offset. Should be non-negative int. Defaults to 0.
            **filters: Various filters to tweak the search query.
                Available String filter keys:
                - profile_key, service_key1, service_key2, key1, ..., key10.
                Available String filter types:
                - single value: Storage.find_one(..., key1="v1"),
                - list of values: Storage.find_one(..., key1=["v1", "v2"]),
                - with $not operator: Storage.find_one(..., key1={"$not": "v1"}, key2={"$not":["v1", "v2"]}).

                Available Int filter keys:
                - version, range_key1, ..., range_key10.
                Available Int filter types:
                - single value: Storage.find_one(..., range_key1=1),
                - list of values: Storage.find_one(..., range_key1=[1, 2]),
                - with $not operator: Storage.find_one(..., range_key1={"$not": 1}, range_key2={"$not":[1, 2]}),
                - with $gt operator: Storage.find_one(..., range_key1={"$gt": 1}),
                - with $gte operator: Storage.find_one(..., range_key1={"$gte": 1}),
                - with $lt operator: Storage.find_one(..., range_key1={"$lt": 1}),
                - with $lte operator: Storage.find_one(..., range_key1={"$lte": 1}),
                - with comparison operators combination: Storage.find_one(..., range_key1={"$gt": 1, $lte": 10}).

        Returns:
            Union[None, Dict[str, Dict]]:
                Found record (if any) or None:
                    {
                        "record": TRecord,
                    }

        Raises:
            StorageClientException: in case method param validation fails.
            StorageServerException: in case InCountry server (either storage server or auth server) responds with error.
            StorageException: in any other cases.
        """

        result = self.find(country=country, limit=1, offset=offset, **filters)
        return {"record": result["records"][0]} if len(result["records"]) else None

    @validate_model(Country)
    @validate_model(Record)
    def delete(self, country: str, record_key: str) -> Dict[str, bool]:
        """Deletes record for the given record_key

        Args:
            country:  Country to search record in
            record_key: Record primary key/identifier

        Returns:
            Dict[str, bool]:
                {"success": True} in case the record is successfully deleted

        Raises:
            StorageClientException: in case method param validation fails.
            StorageServerException: in case InCountry server (either storage server or auth server) responds with error
                (e.g. if record does not exist for the given record_key).
            StorageException: in any other cases.
        """

        record_key_hashed = get_salted_hash(self.normalize_key(record_key), self.env_id)
        self.http_client.delete(country=country, record_key=record_key_hashed)
        return {"success": True}

    @validate_encryption_enabled
    @validate_model(Country)
    @validate_model(FindFilter)
    def migrate(self, country: str, limit: Optional[int] = FIND_LIMIT) -> Dict[str, int]:
        """Migrates records in InCountry storage to the latest encryption key.

        Unavailable when encrypt=False is passed to Storage constructor

        Args:
            country: Country to migrate records in
            limit: Maximum amount of records to be migrated at once. Max limit is 100. Defaults to 100.

        Returns:
            Dict[str, int]:
                Migration result - total amount of successfully migrated records and total records left to migrate
                (total records left with other encryption key versions):
                {
                    "migrated": int,
                    "total_left": int,
                }

        Raises:
            StorageClientException: in case method param validation fails (or in case encryption is disabled).
            StorageServerException: in case InCountry server (either storage server or auth server) responds with error
                (e.g. if record does not exist for the given record_key).
            StorageException: in any other cases.
        """
        current_secret_version = self.crypto.get_current_secret_version()
        find_res = self.find(country=country, limit=limit, version={"$not": current_secret_version})
        records_to_migrate_count = len(find_res["records"])

        if records_to_migrate_count > 0:
            self.batch_write(country=country, records=find_res["records"])

        return_data = {
            "migrated": records_to_migrate_count,
            "total_left": find_res["meta"]["total"] - records_to_migrate_count,
        }
        if "errors" in find_res:
            return_data["errors"] = find_res["errors"]

        return return_data

    @validate_model(Country)
    @validate_model(AttachmentCreate)
    def add_attachment(
        self, country: str, record_key: str, file: Union[BinaryIO, str], mime_type: str = None, upsert: bool = False
    ) -> Dict[str, Union[str, int, datetime]]:
        record_key = get_salted_hash(self.normalize_key(record_key), self.env_id)
        return {
            "attachment_meta": self.http_client.add_attachment(
                country=country, record_key=record_key, file=file, upsert=upsert, mime_type=mime_type
            )
        }

    @validate_model(Country)
    @validate_model(AttachmentRequest)
    def get_attachment_file(self, country: str, record_key: str, file_id: str):
        record_key = get_salted_hash(self.normalize_key(record_key), self.env_id)
        res = self.http_client.get_attachment_file(country=country, record_key=record_key, file_id=file_id)
        return {
            "attachment_data": res,
        }

    @validate_model(Country)
    @validate_model(AttachmentRequest)
    def get_attachment_meta(self, country: str, record_key: str, file_id: str):
        record_key = get_salted_hash(self.normalize_key(record_key), self.env_id)
        return {
            "attachment_meta": self.http_client.get_attachment_meta(
                country=country, record_key=record_key, file_id=file_id
            )
        }

    @validate_model(Country)
    @validate_model(AttachmentRequest)
    @validate_model(AttachmentMetaUpdate)
    def update_attachment_meta(
        self, country: str, record_key: str, file_id: str, filename: str = None, mime_type: str = None
    ):
        record_key = get_salted_hash(self.normalize_key(record_key), self.env_id)
        meta = {}
        if filename is not None:
            meta["filename"] = filename
        if mime_type is not None:
            meta["mime_type"] = mime_type
        return {
            "attachment_meta": self.http_client.update_attachment_meta(
                country=country, record_key=record_key, file_id=file_id, meta=meta
            )
        }

    @validate_model(Country)
    @validate_model(AttachmentRequest)
    def delete_attachment(self, country: str, record_key: str, file_id: str):
        record_key = get_salted_hash(self.normalize_key(record_key), self.env_id)
        self.http_client.delete_attachment(country=country, record_key=record_key, file_id=file_id)
        return {"success": True}

    ###########################################
    # Common functions
    ###########################################
    def log(self, *args):
        if self.debug:
            print("[incountry] ", args)

    def encrypt_record(self, record):
        return encrypt_record(
            self.crypto,
            record,
            self.env_id,
            normalize_keys=self.options.normalize_keys,
            hash_search_keys=self.options.hash_search_keys,
        )

    def decrypt_record(self, record):
        return decrypt_record(self.crypto, record)

    def normalize_key(self, key):
        return normalize_key(key, self.options.normalize_keys)
