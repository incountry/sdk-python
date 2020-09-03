InCountry Storage SDK
============
[![Build Status](https://travis-ci.com/incountry/sdk-python.svg?branch=master)](https://travis-ci.com/incountry/sdk-python)
[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=incountry_sdk-python&metric=alert_status)](https://sonarcloud.io/dashboard?id=incountry_sdk-python)
[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=incountry_sdk-python&metric=coverage)](https://sonarcloud.io/dashboard?id=incountry_sdk-python)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=incountry_sdk-python&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=incountry_sdk-python)

Installation
-----
The recommended way to install the SDK is to use `pipenv` (or `pip`):
```
$ pipenv install incountry
```

Countries List
----
For a full list of supported countries and their codes please [follow this link](countries.md).

Usage
-----
To access your data in InCountry using Python SDK, you need to create an instance of `Storage` class.
```python
class Storage:
    def __init__(
        self,
        environment_id: Optional[str] = None,   # Required to be passed in, or as environment variable INC_API_KEY
        api_key: Optional[str] = None,          # Required when using API key authorization, or as environment variable
        client_id: Optional[str] = None,        # Required when using oAuth authorization, can be also set via INC_CLIENT_ID
        client_secret: Optional[str] = None,    # Required when using oAuth authorization, can be also set via INC_CLIENT_SECRET
        endpoint: Optional[str] = None,         # Optional. Defines API URL. Can also be set up using environment variable INC_ENDPOINT
        encrypt: Optional[bool] = True,         # Optional. If False, encryption is not used
        debug: Optional[bool] = False,          # Optional. If True enables some debug logging
        options: Optional[Dict[str, Any]] = {}, # Optional. Use it to fine-tune some configurations
        custom_encryption_configs: Optional[List[dict]] = None, # Optional. List of custom encryption configurations
        secret_key_accessor: Optional[SecretKeyAccessor] = None, # Instance of SecretKeyAccessor class. Used to fetch encryption secret
    ):
        ...
```

---
**WARNING**

API Key authorization is being deprecated. We keep backwards compatibility for `api_key` param but you no longer can get API keys (neither old nor new) from your dashboard.

---

`client_id`, `client_secret`,  and `environment_id` can be fetched from your dashboard on `Incountry` site.


`endpoint` defines API URL and is used to override default one.

You can turn off encryption (not recommended). Set `encrypt` property to `false` if you want to do this.

`options` allows you to tweak some SDK configurations
```python
{
    "http_options": {
        "timeout": int,         # In seconds. Should be greater than 0
    },
    "auth_endpoints": dict,     # custom endpoints regional map to use for fetching oAuth tokens

    "countries_endpoint": str,  # If your PoPAPI configuration relies on a custom PoPAPI server
                                # (rather than the default one) use `countriesEndpoint` option
                                # to specify the endpoint responsible for fetching supported countries list

    "endpoint_mask": str,       # Defines API base hostname part to use.
                                # If set, all requests will be sent to https://${country}${endpointMask} host
                                # instead of the default one (https://${country}-mt-01.api.incountry.io)
}
```

Below is an example how to create a storage instance
```python
from incountry import Storage, SecretKeyAccessor

storage = Storage(
    api_key="<api_key>",
    environment_id="<env_id>",
    debug=True,
    secret_key_accessor=SecretKeyAccessor(lambda: "password"),
    options={
        "http_options": {
            "timeout": 5
        },
        "countries_endpoint": "https://private-pop.incountry.io/countries",
        "endpoint_mask" ".private-pop.incountry.io",
    }
)
```


#### oAuth Authentication
SDK also supports oAuth authentication credentials instead of plain API key authorization. oAuth authentication flow is mutually exclusive with API key authentication - you will need to provide either API key or oAuth credentials.

Below is the example how to create storage instance with oAuth credentials (and also provide custom oAuth endpoint):
```python
from incountry import Storage, SecretKeyAccessor

storage = Storage(
    client_id="<client_id>",
    client_secret="<client_secret>",
    environment_id="<env_id>",
    debug=True,
    secret_key_accessor=SecretKeyAccessor(lambda: "password"),
    options={
        "auth_endpoints": {
            "default": "https://auth-server-default.com",
            "emea": "https://auth-server-emea.com",
            "apac": "https://auth-server-apac.com",
            "amer": "https://auth-server-amer.com",
        }
    }
)
```


#### Encryption key/secret

`secret_key_accessor` is used to pass a key or secret used for encryption.

Note: even though SDK uses PBKDF2 to generate a cryptographically strong encryption key, you must make sure you provide a secret/password which follows modern security best practices and standards.

`SecretKeyAccessor` class constructor allows you to pass a function that should return either a string representing your secret or a dict (we call it `secrets_data` object):

```python
{
  "secrets": [{
       "secret": str,
       "version": int, # Should be an integer greater than or equal to 0
       "isKey": bool,  # Should be True only for user-defined encryption keys
    }
  }, ....],
  "currentVersion": int,
}
```

`secrets_data` allows you to specify multiple keys/secrets which SDK will use for decryption based on the version of the key or secret used for encryption. Meanwhile SDK will encrypt only using key/secret that matches `currentVersion` provided in `secrets_data` object.

This enables the flexibility required to support Key Rotation policies when secrets/keys need to be changed with time. SDK will encrypt data using current secret/key while maintaining the ability to decrypt records encrypted with old keys/secrets. SDK also provides a method for data migration which allows to re-encrypt data with the newest key/secret. For details please see `migrate` method.

SDK allows you to use custom encryption keys, instead of secrets. Please note that user-defined encryption key should be a 32-characters 'utf8' encoded string as required by AES-256 cryptographic algorithm.


Here are some examples how you can use `SecretKeyAccessor`.
```python
# Get secret from variable
from incountry import SecretKeyAccessor

password = "password"
secret_key_accessor = SecretKeyAccessor(lambda: password)

# Get secrets via http request
from incountry import SecretKeyAccessor
import requests as req

def get_secrets_data():
    url = "<your_secret_url>"
    r = req.get(url)
    return r.json() # assuming response is a `secrets_data` object

secret_key_accessor = SecretKeyAccessor(get_secrets_data)
```

### Writing data to Storage

Use `write` method in order to create/replace (by `record_key`) a record.
```python
def write(self, country: str, record_key: str, **record_data: Union[str, int]) -> Dict[str, TRecord]:
    ...


# write returns created record dict on success
{
    "record": Dict
}
```


Below is the example of how you may use `write` method
```python
write_result = storage.write(
    country="us",
    record_key="user_1",
    body="some PII data",
    profile_key="customer",
    range_key1=10000,
    key1="english",
    key2="rolls-royce",
)

# write_result would be as follows
write_result = {
    "record": {
        "record_key": "user_1",
        "body": "some PII data",
        "profile_key": "customer",
        "range_key1": 10000,
        "key1": "english",
        "key2": "rolls-royce",
    }
}
```

For the list of possible `record_data` kwargs see section below


#### List of available record fields
v3.0.0 release introduced a series of new fields available for storage. Below is an exhaustive list of fields available for storage in InCountry along with their types and  storage methods - each field is either encrypted, hashed or stored as is:
```python
# String fields, hashed
record_key
key1
key2
key3
key4
key5
key6
key7
key8
key9
key10
profile_key
service_key1
service_key2

# String fields, encrypted
body
precommit_body

# Int fields, plain
range_key1
range_key2
range_key3
range_key4
range_key5
range_key6
range_key7
range_key8
range_key9
range_key10
```

#### Batches
Use `batch_write` method to create/replace multiple records at once.

```python
def batch_write(self, country: str, records: List[TRecord]) -> Dict[str, List[TRecord]]:
    ...


# batch_write returns the following dict of created records
{
    "records": List
}
```

Below you can see the example of how to use this method
```python
batch_result = storage.batch_write(
    country="us",
    records=[
        {"record_key": "key1", "body": "body1", ...},
        {"record_key": "key2", "body": "body2", ...},
    ],
)

# batch_result would be as follows
batch_result = {
    "records": [
        {"record_key": "key1", "body": "body1", ...},
        {"record_key": "key2", "body": "body2", ...},
    ]
}
```


### Reading stored data

Stored record can be read by `record_key` using `read` method. It accepts an object with two fields: `country` and `record_key`
```python
def read(self, country: str, record_key: str) -> Dict[str, TRecord]:
    ...


# read returns record dict if the record is found
{
    "record": Dict
}
```

#### Date fields
Use `created_at` and `updated_at` fields to access date-related information about records. `created_at` indicates date when the record was initially created in the target country. `updated_at` shows the date of the latest write operation for the given recordKey

You can use `read` method as follows:
```python
read_result = storage.read(country="us", record_key="user1")

# read_result would be as follows
read_result = {
    "record": {
        "record_key": "user_1",
        "body": "some PII data",
        "profile_key": "customer",
        "range_key1": 10000,
        "key1": "english",
        "key2": "rolls-royce",
        "created_at": datetime.datetime(...),
        "updated_at": datetime.datetime(...),
    }
}
```

### Find records

It is possible to search records by keys or version using `find` method.
```python
def find(
        self,
        country: str,
        limit: Optional[int] = FIND_LIMIT,
        offset: Optional[int] = 0,
        **filters: Union[TIntFilter, TStringFilter],
    ) -> Dict[str, Any]:
    ...
```
Note: SDK returns 100 records at most.

The return object looks like the following:
```python
{
    "data": List,
    "errors": List, # optional
    "meta": {
        "limit": int,
        "offset": int,
        "total": int,  # total records matching filter, ignoring limit
    }
}
```
You can use the following options to search by hashed string keys from the [list above](#list-of-available-record-fields):
```python
# single value
key1="value1" # records with key1 equal to "value1"

# list of values
key2=["value1", "value2"] # records with key2 equal to "value1" or "value2"

# dict with $not operator
key3={"$not": "value1"} # records with key3 not equal "value1"
key4={"$not": ["value1", "value2"]} # records with key4 equal to neither "value1" or "value2"
```


You can use the following options to search by int keys from the [list above](#list-of-available-record-fields):
```python
# single value
range_key1=1 # records with range_key1 equal to 1

# list of values
range_key2=[1, 2] # records with range_key2 equal to 1 or 2

# dict with comparison operators
range_key3={"$gt": 1} # records with range_key3 greater than 1
range_key4={"$gte": 1} # records with range_key4 greater than or equal to 1
range_key5={"$lt": 1} # records with range_key5 less than 1
range_key6={"$lte": 1} # records with range_key6 less than or equal to 1

# you can combine different comparison operators
range_key7={"$gt": 1, "$lte": 10} # records with range_key7 greater than 1 and less than or equal to 10

# you can't combine similar comparison operators - e.g. $gt and $gte, $lt and $lte
```


You can use the following option to search by `version` (encryption key version):
```python
# single value
version=1 # records with version equal to 1

# list of values
version=[1, 2] # records with version equal to 1 or 2

# dict with $not operator
version={"$not": 1} # records with version not equal 1
version={"$not": [1, 2]} # records with version equal to neither 1 or 2
```

Here is the example of how `find` method can be used:
```python
find_result = storage.find(country="us", limit=10, offset=10, key1="value1", key2=["value2", "value3"])

# find_result would be as follows
find_result = {
    "data": [
        {
            "record_key": "<record_key>",
            "body": "<body>",
            "key1": "value1",
            "key2": "value2",
            "created_at": datetime.datetime(...),
            "updated_at": datetime.datetime(...),
            ...
        }
    ],
    "meta": {
        "limit": 10,
        "offset": 10,
        "total": 100,
    }
}
```

#### Error handling

There could be a situation when `find` method will receive records that could not be decrypted.
For example, if one changed the encryption key while the found data is encrypted with the older version of that key.
In such cases find() method return data will be as follows:

```python
{
    "data": [...],  # successfully decrypted records
    "errors": [{
        "rawData",  # raw record which caused decryption error
        "error",    # decryption error description
    }, ...],
    "meta": { ... }
}
```

### Find one record matching filter

If you need to find only one of the records matching filter, you can use the `find_one` method.
```python
def find_one(
        self, country: str, offset: Optional[int] = 0, **filters: Union[TIntFilter, TStringFilter],
    ) -> Union[None, Dict[str, Dict]]:
    ...


# If record is not found, find_one will return `None`. Otherwise it will return record dict
{
    "record": Dict
}
```

Below is the example of using `find_one` method:
```python
find_one_result = storage.find_one(country="us", key1="english", key2=["rolls-royce", "bmw"])

# find_one_result would be as follows
find_one_result = {
    "record": {
        "record_key": "user_1",
        "body": "some PII data",
        "profile_key": "customer",
        "range_key1": 10000,
        "key1": "english",
        "key2": "rolls-royce",
    }
}
```


### Delete records
Use `delete` method in order to delete a record from InCountry storage. It is only possible using `record_key` field.
```python
def delete(self, country: str, record_key: str) -> Dict[str, bool]:
    ...


# delete returns the following dict on success
{
    "success": True
}
```

Below is the example of using delete method:
```python
delete_result = storage.delete(country="us", record_key="<record_key>")

# delete_result would be as follows
delete_result = {
    "success": True
}
```

## Data Migration and Key Rotation support
Using `secret_key_accessor` that provides `secrets_data` object enables key rotation and data migration support.

SDK introduces `migrate` method which allows you to re-encrypt data encrypted with old versions of the secret.
```python
def migrate(self, country: str, limit: Optional[int] = FIND_LIMIT) -> Dict[str, int]:
    ...


# migrate returns the following dict with meta information
{
    "migrated": int   # the amount of records migrated
	"total_left": int # the amount of records left to migrate (amount of records with version
                      # different from `currentVersion` provided by `secret_key_accessor`)
}
```
You should specify `country` you want to conduct migration in and `limit` for precise amount of records to migrate.


Note: maximum number of records migrated per request is 100

For a detailed example of a migration script please see `/examples/full_migration.py`

Error Handling
-----

InCountry Python SDK throws following Exceptions:

- **StorageClientException** - used for various input validation errors. Can be thrown by all public methods.

- **StorageServerException** - thrown if SDK failed to communicate with InCountry servers or if server response validation failed.

- **StorageCryptoException** - thrown during encryption/decryption procedures (both default and custom). This may be a sign of malformed/corrupt data or a wrong encryption key provided to the SDK.

- **StorageException** - general exception. Inherited by all other exceptions

We suggest gracefully handling all the possible exceptions:

```python
try:
    # use InCountry Storage instance here
except StorageClientException as e:
    # some input validation error
except StorageServerException as e:
    # some server error
except StorageCryptoException as e:
    # some encryption error
except StorageException as e:
    # general error
except Exception as e:
    # something else happened not related to InCountry SDK
```

Custom Encryption Support
-----
SDK supports the ability to provide custom encryption/decryption methods if you decide to use your own algorithm instead of the default one.

`Storage` constructor allows you to pass `custom_encryption_configs` param - an array of custom encryption configurations with the following schema, which enables custom encryption:

```python
{
    "encrypt": Callable,
    "decrypt": Callable,
    "isCurrent": bool,
    "version": str
}
```

Both `encrypt` and `decrypt` attributes should be functions implementing the following interface (with exactly same argument names)

```python
encrypt(input:str, key:bytes, key_version:int) -> str:
    ...

decrypt(input:str, key:bytes, key_version:int) -> str:
    ...
```
They should accept raw data to encrypt/decrypt, key data (represented as bytes array) and key version received from `SecretKeyAccessor`.
The resulted encrypted/decrypted data should be a string.

---
**NOTE**

You should provide a specific encryption key via `secrets_data` passed to `SecretKeyAccessor`. This secret should use flag `isForCustomEncryption` instead of the regular `isKey`.

```python
secrets_data = {
  "secrets": [{
       "secret": "<secret for custom encryption>",
       "version": 1,
       "isForCustomEncryption": True,
    }
  }],
  "currentVersion": 1,
}

secret_accessor = SecretKeyAccessor(lambda: secrets_data)
```
---

`version` attribute is used to differ one custom encryption from another and from the default encryption as well.
This way SDK will be able to successfully decrypt any old data if encryption changes with time.

`isCurrent` attribute allows to specify one of the custom encryption configurations to use for encryption. Only one configuration can be set as `"isCurrent": True`.

If none of the configurations have `"isCurrent": True` then the SDK will use default encryption to encrypt stored data. At the same time it will keep the ability to decrypt old data, encrypted with custom encryption (if any).

Here's an example of how you can set up SDK to use custom encryption (using Fernet encryption method from https://cryptography.io/en/latest/fernet/)

```python
import os

from incountry import InCrypto, SecretKeyAccessor, Storage
from cryptography.fernet import Fernet

def enc(input, key, key_version):
    cipher = Fernet(key)
    return cipher.encrypt(input.encode("utf8")).decode("utf8")

def dec(input, key, key_version):
    cipher = Fernet(key)
    return cipher.decrypt(input.encode("utf8")).decode("utf8")

custom_encryption_configs = [
    {
        "encrypt": enc,
        "decrypt": dec,
        "version": "test",
        "isCurrent": True,
    }
]

key = InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH))  # Fernet uses 32-byte length key encoded using base64

secret_key_accessor = SecretKeyAccessor(
    lambda: {
        "currentVersion": 1,
        "secrets": [{"secret": key, "version": 1, "isForCustomEncryption": True}],
    }
)

storage = Storage(
    api_key="<api_key>",
    environment_id="<env_id>",
    secret_key_accessor=secret_key_accessor,
    custom_encryption_configs=custom_encryption_configs,
)

storage.write(country="us", record_key="<record_key>", body="<body>")
```

Testing Locally
-----

1. In terminal run `pipenv run tests` for unit tests
2. In terminal run `pipenv run integrations` to run integration tests
