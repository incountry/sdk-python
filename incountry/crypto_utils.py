import hashlib
import json

from .incountry_crypto import InCrypto
from .exceptions import StorageClientException

from .models import Record

HASHABLE_KEYS = [
    "record_key",
    "profile_key",
    "service_key1",
    "service_key2",
    "key1",
    "key2",
    "key3",
    "key4",
    "key5",
    "key6",
    "key7",
    "key8",
    "key9",
    "key10",
]

KEYS_TO_OMIT_ON_ENCRYPTION = [
    "created_at",
    "updated_at",
]


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

    (enc_data, key_version, is_encrypted) = crypto.encrypt(json.dumps(body))
    res["body"] = enc_data
    res["version"] = key_version
    res["is_encrypted"] = is_encrypted
    if res.get("precommit_body"):
        (enc_precommit_body, *_) = crypto.encrypt(res["precommit_body"])
        res["precommit_body"] = enc_precommit_body

    return {
        key: value
        for key, value in res.items()
        if value is not None and key in Record.__fields__ and key not in KEYS_TO_OMIT_ON_ENCRYPTION
    }


def decrypt_record(crypto, record):
    validate_crypto(crypto)
    res = dict(record)

    if res.get("body"):
        res["body"] = crypto.decrypt(res["body"], res["version"])
        if res.get("precommit_body"):
            res["precommit_body"] = crypto.decrypt(res["precommit_body"], res["version"])
        if is_json(res["body"]):
            body = json.loads(res["body"])
            if body.get("payload"):
                res["body"] = body.get("payload")
            else:
                res["body"] = None
            for k in HASHABLE_KEYS:
                if record.get(k) and body["meta"].get(k):
                    res[k] = body["meta"][k]
            if body["meta"].get("key", None):
                res["record_key"] = body["meta"].get("key")

    return {key: value for key, value in res.items() if value is not None and key in Record.__fields__}
