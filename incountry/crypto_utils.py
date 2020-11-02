import hashlib
import json
from copy import deepcopy
from pydantic import BaseModel

from .incountry_crypto import InCrypto
from .exceptions import StorageClientException

from .models import FindFilter, FindFilterOperators, Record

SERVICE_KEYS = [
    "record_key",
    "profile_key",
    "service_key1",
    "service_key2",
]

SEARCH_KEYS = [
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

KEYS_TO_HASH = SERVICE_KEYS + SEARCH_KEYS

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


def hash_string_key_value(value, salt, normalize=False):
    if isinstance(value, list):
        return [get_salted_hash(normalize_key(x, normalize=normalize), salt) for x in value]
    return get_salted_hash(normalize_key(value, normalize=normalize), salt)


def sanitize_obj_for_model(obj: dict, model: BaseModel):
    res = deepcopy(obj)
    for key in obj:
        if key not in model.__fields__ or obj[key] is None:
            del res[key]
    return res


def hash_object_record_keys(obj, salt, normalize_keys=False, hash_search_keys=True, hash_for_find=False):
    res = {}

    for key, value in obj.items():
        if value is None:
            continue

        if key not in KEYS_TO_HASH:
            res[key] = value
            continue

        if FindFilterOperators.NOT in value:
            res[key] = {
                key: {
                    FindFilterOperators.NOT: hash_string_key_value(
                        value[FindFilterOperators.NOT], salt, normalize=normalize_keys
                    )
                }
            }
        elif hash_search_keys or key not in SEARCH_KEYS:
            res[key] = hash_string_key_value(value, salt, normalize=normalize_keys)
    return res


def encrypt_record(crypto, record, salt, normalize_keys=False, hash_search_keys=True):
    validate_crypto(crypto)
    validate_is_string(salt, "salt")

    meta = {}
    for k in KEYS_TO_HASH:
        if record.get(k, None):
            meta[k] = record.get(k)

    res = hash_object_record_keys(record, salt, normalize_keys=normalize_keys, hash_search_keys=hash_search_keys)

    body_to_enc = {"meta": meta, "payload": res.get("body", None)}

    (res["body"], res["version"], res["is_encrypted"]) = crypto.encrypt(json.dumps(body_to_enc))
    if res.get("precommit_body"):
        (res["precommit_body"], *_) = crypto.encrypt(res["precommit_body"])

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
            for k in KEYS_TO_HASH:
                if record.get(k) and body["meta"].get(k):
                    res[k] = body["meta"][k]
            if body["meta"].get("key", None):
                res["record_key"] = body["meta"].get("key")

    return {key: value for key, value in res.items() if value is not None and key in Record.__fields__}
