InCountry Storage SDK
============

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
from incountry import Storage

storage = Storage(
    api_key="string",              # Required to be passed in, or as environment variable INC_API_KEY
    environment_id="string",       # Required to be passed in, or as environment variable INC_ENVIRONMENT_ID
    endpoint="string",             # Optional. Defines API URL
    encrypt=bool,                  # Optional. If False, encryption is not used
    debug=bool,                    # Optional. If True enables some debug logging
    secret_key_accessor=accessor,  # Instance of SecretKeyAccessor class. Used to fetch encryption secret
)
```
`api_key` and `environment_id` can be fetched from your dashboard on `Incountry` site.

`endpoint` defines API URL and is used to override default one.

You can turn off encryption (not recommended). Set `encrypt` property to `false` if you want to do this.

#### Encryption key

`secret_key_accessor` is used to pass a secret used for encryption.

Note: even though PBKDF2 is used internally to generate a cryptographically strong encryption key, you must make sure that you use strong enough password.

Here are some examples how you can use `SecretKeyAccessor`.
```python
# Get secret from variable
from incountry import SecretKeyAccessor

password = "password"
secret_key_accessor = SecretKeyAccessor(lambda: password)

# Get secret via http request
from incountry import SecretKeyAccessor
import requests as req

def get_secret():
    url = "<your_secret_url>"
    r = req.get(url)
    return r.json().get("secret") # assuming response is {"secret": "password"}

secret_key_accessor = SecretKeyAccessor(get_secret)
```

### Writing data to Storage

Use `write` method in order to create a record.
```python
record = storage.write(
    country="string",      # Required country code of where to store the data
    key="string",          # Required record key
    body="string",         # Optional payload
    profile_key="string",  # Optional
    range_key=integer,     # Optional
    key2="string",         # Optional
    key3="string",         # Optional
)

# `write` returns created record on success
```
#### Encryption
InCountry uses client-side encryption for your data. Note that only body is encrypted. Some of other fields are hashed.
Here is how data is transformed and stored in InCountry database:
```python
{
    key,          # hashed
    body,         # encrypted
    profile_key,  # hashed
    range_key,    # plain
    key2,         # hashed
    key3,         # hashed
}
```
### Reading stored data

Stored record can be read by `key` using `readAsync` method. It accepts an object with two fields: `country` and `key`
```python
record = storage.read(
    country="string",      # Required country code
    key="string",          # Required record key
)
```

### Find records

It is possible to search by random keys using `find` method.
```python
records = storage.find(country, limit, offset, **filter_kwargs)
```
Parameters:
`country` - country code,
`limit` - maximum amount of records you'd like to retrieve. Defaults to 100,
`offset` - specifies the number of records to skip,
`filter_kwargs` - a filter parameters.

Here is the example of how `find` method can be used:
```python
records = storage.find(country="us", limit=10, offset=10, key2="kitty", key3=["mew", "purr"])
```
This call returns all records with `key2` equals `kitty` AND `key3` equals `mew` OR `purr`. The `options` parameter defines the number of records to return and the starting index. It can be used for pagination. Note: SDK returns 100 records at most.

The return object looks like the following:
```python
{
    "data": [...],
    "errors": [...],   # optional
    "meta": {
        "limit": 10,
        "offset": 10,
        "total": 124,  # total records matching filter, ignoring limit
    }
}
```
You can use the following types for filter parameters.
Single value:
```python
key2="kitty"
```
One of the values:
```python
key3=["mew", "purr"]
```
`range_key` is a numeric field so you can use range filter requests, for example:
```python
range_key={"$lt": 1000} # search for records with range_key < 1000
```
Available request options for `range_key`: `$lt`, `$lte`, `$gt`, `$gte`.

You can search by any keys: `key`, `key2`, `key3`, `profile_key`, `range_key`.

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

If you need to find the first record matching filter, you can use the `find_one` method.
```python
record = storage.find_one(country, offset, **filter_kwargs)
```
If record is not found, it will return `None`.

### Delete records
Use `deleteAsync` method in order to delete a record from InCountry storage. It is only possible using `key` field.
```python
storage.delete(
    country="string",      # Required country code
    key="string",          # Required record key
)

# `delete` will raise an Exception if fails
```

Testing Locally
-----

1. In terminal run `pipenv run tests` for unit tests
2. In terminal run `pipenv run integrations` to run integration tests
