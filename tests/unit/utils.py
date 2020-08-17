from random import randrange, choice, choices
import string
import uuid
import sys

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
ALL_FIELDS = STRING_FIELDS + INT_FIELDS


def get_random_str():
    return "".join(choices(string.ascii_uppercase + string.ascii_lowercase, k=10))


def generate_record(fields, use_last_field_value=False, last_field_value=None, allow_invalid_record=True):
    record = {}
    for field in fields:
        record[field] = str(uuid.uuid1()) if field in STRING_FIELDS else randrange(sys.maxsize)
    if use_last_field_value:
        if allow_invalid_record:
            record[fields[-1]] = last_field_value
        elif fields[-1] != "record_key":
            record[fields[-1]] = last_field_value

    return record


def get_test_records(use_last_field_value=False, last_field_value=None):
    return [
        generate_record(ALL_FIELDS[: i + 1], use_last_field_value, last_field_value, allow_invalid_record=False)
        for i in range(len(ALL_FIELDS))
    ]


def get_invalid_records():
    return [
        generate_record(ALL_FIELDS[: i + 1], use_last_field_value=True, last_field_value=["not a ", "str or int"])
        for i in range(len(ALL_FIELDS))
    ]


def get_valid_find_filter_test_options():
    res = []

    for field in ALL_FIELDS:
        if field in ["body", "precommit_body"]:
            continue
        if field in STRING_FIELDS:
            res.append({field: get_random_str()})
            res.append({field: [get_random_str(), get_random_str()]})
        if field in INT_FIELDS:
            res.append({field: randrange(sys.maxsize)})
            res.append({field: [randrange(sys.maxsize), randrange(sys.maxsize)]})

            res.append({field: {"$gt": randrange(sys.maxsize)}})
            res.append({field: {"$lt": randrange(sys.maxsize)}})
            res.append({field: {"$gte": randrange(sys.maxsize)}})
            res.append({field: {"$lte": randrange(sys.maxsize)}})

            res.append({field: {"$lte": randrange(sys.maxsize), "$gte": randrange(sys.maxsize)}})
            res.append({field: {"$lte": randrange(sys.maxsize), "$gt": randrange(sys.maxsize)}})
            res.append({field: {"$lt": randrange(sys.maxsize), "$gte": randrange(sys.maxsize)}})
            res.append({field: {"$lt": randrange(sys.maxsize), "$gt": randrange(sys.maxsize)}})

    res.append({"version": randrange(sys.maxsize)})
    res.append({"version": [randrange(sys.maxsize), randrange(sys.maxsize)]})

    res.append({"version": {"$not": randrange(sys.maxsize)}})

    res.append({"version": {"$gt": randrange(sys.maxsize)}})
    res.append({"version": {"$lt": randrange(sys.maxsize)}})
    res.append({"version": {"$gte": randrange(sys.maxsize)}})
    res.append({"version": {"$lte": randrange(sys.maxsize)}})

    res.append({"version": {"$lte": randrange(sys.maxsize), "$gte": randrange(sys.maxsize)}})
    res.append({"version": {"$lte": randrange(sys.maxsize), "$gt": randrange(sys.maxsize)}})
    res.append({"version": {"$lt": randrange(sys.maxsize), "$gte": randrange(sys.maxsize)}})
    res.append({"version": {"$lt": randrange(sys.maxsize), "$gt": randrange(sys.maxsize)}})

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


def omit(d, *keys):
    return {x: d[x] for x in d if x not in keys}
