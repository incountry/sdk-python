import hashlib
import json

from .incountry_crypto import InCrypto
from .exceptions import StorageClientException

HASHABLE_KEYS = ["key", "key2", "key3", "profile_key"]


def validate_crypto(crypto):
    if not isinstance(crypto, InCrypto):
        raise StorageClientException(f"'crypto' argument should be an instance of InCrypto. Got {type(crypto)}")


def validate_is_string(value, arg_name):
    if not isinstance(value, str):
        raise StorageClientException(f"'{arg_name}' argument should be of type string. Got {type(value)}")


def is_json(data):
    try:
        json.loads(data)
    except ValueError:
        return False
    return True


def hash(data):
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def normalize_key(key, normalize=False):
    if not isinstance(key, str):
        return key
    return key.lower() if normalize else key


def get_salted_hash(value, salt):
    validate_is_string(value, "value")
    validate_is_string(salt, "salt")
    return hash(value + ":" + salt)


def encrypt_record(crypto, record, salt, normalize_keys=False):
    validate_crypto(crypto)
    validate_is_string(salt, "salt")
    res = dict(record)
    body = {"meta": {}, "payload": None}
    for k in HASHABLE_KEYS:
        if res.get(k, None):
            body["meta"][k] = res.get(k)
            res[k] = get_salted_hash(normalize_key(res[k], normalize_keys), salt)
    if res.get("body"):
        body["payload"] = res.get("body")

    [enc_data, key_version] = crypto.encrypt(json.dumps(body))
    res["body"] = enc_data
    res["version"] = key_version

    return {key: value for key, value in res.items() if value is not None}


def decrypt_record(crypto, record):
    validate_crypto(crypto)
    res = dict(record)
    if res.get("body"):
        res["body"] = crypto.decrypt(res["body"], res["version"])
        if is_json(res["body"]):
            body = json.loads(res["body"])
            if body.get("payload"):
                res["body"] = body.get("payload")
            else:
                res["body"] = None
            for k in HASHABLE_KEYS:
                if record.get(k) and body["meta"].get(k):
                    res[k] = body["meta"][k]

    return {key: value for key, value in res.items() if value is not None}
