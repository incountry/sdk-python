from random import randrange, choice, choices, random
import string
import sys
from datetime import datetime, timedelta, timezone
import mimetypes


from incountry.models import MAX_LEN_NON_HASHED


STRING_FIELDS = [
    "record_key",
    "body",
    "precommit_body",
    "service_key1",
    "service_key2",
    "profile_key",
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
INT_FIELDS = [
    "range_key1",
    "range_key2",
    "range_key3",
    "range_key4",
    "range_key5",
    "range_key6",
    "range_key7",
    "range_key8",
    "range_key9",
    "range_key10",
]
DATE_FIELDS = ["created_at", "updated_at"]
ALL_FIELDS = STRING_FIELDS + INT_FIELDS
ALL_FIELDS_WITH_DATES = ALL_FIELDS + DATE_FIELDS


def get_random_str(length=10):
    return choice(string.ascii_uppercase) + "".join(
        choices(string.ascii_uppercase + string.ascii_lowercase, k=length - 1)
    )


def get_random_int():
    return randrange(sys.maxsize)


def get_random_mime_type():
    return choice(list(mimetypes.types_map.values()))


def get_random_datetime(min_year=1900, max_year=datetime.now().year):
    start = datetime(min_year, 1, 1, 00, 00, 00, 00, timezone.utc)
    years = max_year - min_year + 1
    end = start + timedelta(days=365 * years)
    return start + (end - start) * random()


def generate_record(fields, use_last_field_value=False, last_field_value=None, allow_invalid_record=True):
    record = {}
    for field in fields:
        if field in STRING_FIELDS:
            record[field] = get_random_str(MAX_LEN_NON_HASHED)
        if field in INT_FIELDS:
            record[field] = get_random_int()
    if use_last_field_value:
        if allow_invalid_record:
            record[fields[-1]] = last_field_value
        elif fields[-1] != "record_key":
            record[fields[-1]] = last_field_value

    return record


def get_valid_test_record():
    return generate_record(ALL_FIELDS, allow_invalid_record=False)


def get_test_records(use_last_field_value=False, last_field_value=None):
    return [
        generate_record(ALL_FIELDS[: i + 1], use_last_field_value, last_field_value, allow_invalid_record=False)
        for i in range(len(ALL_FIELDS))
    ]


def get_invalid_records():
    return [
        generate_record(
            ALL_FIELDS_WITH_DATES[: i + 1], use_last_field_value=True, last_field_value=["not a ", "str or int"]
        )
        for i in range(len(ALL_FIELDS_WITH_DATES))
    ]


def get_invalid_records_non_hashed():
    res = []
    for i in range(10):
        rec = get_valid_test_record()
        rec.update({"key" + str(i + 1): 257 * "x"})
        res.append(rec)
    return res


def get_valid_find_filter_test_options():
    res = []

    for field in ALL_FIELDS:
        if field in ["body", "precommit_body"]:
            continue
        if field in STRING_FIELDS:
            res.append({field: get_random_str()})
            res.append({field: [get_random_str(), get_random_str()]})
            res.append({field: {"$not": get_random_str()}})
        if field in INT_FIELDS:
            res.append({field: get_random_int()})
            res.append({field: [get_random_int(), get_random_int()]})

            res.append({field: {"$gt": get_random_int()}})
            res.append({field: {"$lt": get_random_int()}})
            res.append({field: {"$gte": get_random_int()}})
            res.append({field: {"$lte": get_random_int()}})

            res.append({field: {"$lte": get_random_int(), "$gte": get_random_int()}})
            res.append({field: {"$lte": get_random_int(), "$gt": get_random_int()}})
            res.append({field: {"$lt": get_random_int(), "$gte": get_random_int()}})
            res.append({field: {"$lt": get_random_int(), "$gt": get_random_int()}})

    res.append({"version": get_random_int()})
    res.append({"version": [get_random_int(), get_random_int()]})

    res.append({"version": {"$not": get_random_int()}})

    res.append({"version": {"$gt": get_random_int()}})
    res.append({"version": {"$lt": get_random_int()}})
    res.append({"version": {"$gte": get_random_int()}})
    res.append({"version": {"$lte": get_random_int()}})

    res.append({"version": {"$lte": get_random_int(), "$gte": get_random_int()}})
    res.append({"version": {"$lte": get_random_int(), "$gt": get_random_int()}})
    res.append({"version": {"$lt": get_random_int(), "$gte": get_random_int()}})
    res.append({"version": {"$lt": get_random_int(), "$gt": get_random_int()}})

    return res


def get_randomcase_record(use_list_values=False):
    return {
        "record_key": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key1": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key2": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key3": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key4": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key5": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key6": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key7": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key8": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key9": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "key10": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "profile_key": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "service_key1": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "service_key2": [get_random_str(), get_random_str()] if use_list_values else get_random_str(),
        "range_key1": 42,
        "range_key2": 42,
        "range_key3": 42,
        "range_key4": 42,
        "range_key5": 42,
        "range_key6": 42,
        "range_key7": 42,
        "range_key8": 42,
        "range_key9": 42,
        "range_key10": 42,
    }


def get_attachment_meta_valid_response():
    return {
        "created_at": get_random_datetime(),
        "updated_at": get_random_datetime(),
        "download_link": get_random_str(),
        "file_id": get_random_str(),
        "filename": get_random_str(),
        "hash": get_random_str(64),
        "mime_type": get_random_mime_type(),
        "size": 100,
    }


def get_attachment_meta_invalid_responses():
    return [
        dict(get_attachment_meta_valid_response(), **{"download_link": 123}),
        dict(get_attachment_meta_valid_response(), **{"download_link": ""}),
        dict(get_attachment_meta_valid_response(), **{"file_id": 123}),
        dict(get_attachment_meta_valid_response(), **{"file_id": ""}),
        dict(get_attachment_meta_valid_response(), **{"filename": 123}),
        dict(get_attachment_meta_valid_response(), **{"filename": ""}),
        dict(get_attachment_meta_valid_response(), **{"hash": 123}),
        dict(get_attachment_meta_valid_response(), **{"hash": ""}),
        dict(get_attachment_meta_valid_response(), **{"hash": "123"}),
        dict(get_attachment_meta_valid_response(), **{"mime_type": 123}),
        dict(get_attachment_meta_valid_response(), **{"mime_type": ""}),
        dict(get_attachment_meta_valid_response(), **{"size": -123}),
        dict(get_attachment_meta_valid_response(), **{"size": ""}),
        dict(get_attachment_meta_valid_response(), **{"size": "invalid size"}),
    ]


def omit(d, *keys):
    return {x: d[x] for x in d if x not in keys}
