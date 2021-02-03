from functools import reduce
from typing import Union, Dict

from pydantic import (
    BaseModel,
    StrictStr,
    StrictInt,
    conint,
    conlist,
    constr,
    validator,
)


from .record import MAX_LEN_NON_HASHED, SEARCH_KEYS


class Operators(str):
    NOT = "$not"
    GT = "$gt"
    GTE = "$gte"
    LT = "$lt"
    LTE = "$lte"


FIND_LIMIT = 100
SEARCH_KEYS_MIN_LEN = 3
SEARCH_KEYS_MAX_LEN = 200

STR_OPERATORS = [Operators.NOT]
COMPARISON_GROUPS = [
    [Operators.GT, Operators.GTE],
    [Operators.LT, Operators.LTE],
]
INT_OPERATORS = [
    Operators.NOT,
    Operators.GT,
    Operators.GTE,
    Operators.LT,
    Operators.LTE,
]


NonEmptyStr = constr(strict=True, min_length=1)
NonEmptyStrList = conlist(StrictStr, min_items=1)
NonEmptyIntList = conlist(StrictInt, min_items=1)

MaxLenStr = constr(strict=True, max_length=MAX_LEN_NON_HASHED)
MaxLenStrList = conlist(MaxLenStr, min_items=1)

OperatorsStrDict = Dict[NonEmptyStr, Union[StrictStr, NonEmptyStrList, None]]
OperatorsIntDict = Dict[NonEmptyStr, Union[StrictInt, NonEmptyIntList, None]]
OperatorsMaxLenStrDict = Dict[NonEmptyStr, Union[MaxLenStr, MaxLenStrList, None]]

StrKey = Union[StrictStr, NonEmptyStrList, None, OperatorsStrDict]
IntKey = Union[StrictInt, NonEmptyIntList, None, OperatorsIntDict]
StrKeyNonHashed = Union[MaxLenStr, MaxLenStrList, None, OperatorsMaxLenStrDict]


class FindFilter(BaseModel):
    limit: conint(ge=1, le=FIND_LIMIT, strict=True) = FIND_LIMIT
    offset: conint(ge=0, strict=True) = 0
    record_key: StrKey = None
    profile_key: StrKey = None
    service_key1: StrKey = None
    service_key2: StrKey = None
    parent_key: StrKey = None
    key1: StrKey = None
    key2: StrKey = None
    key3: StrKey = None
    key4: StrKey = None
    key5: StrKey = None
    key6: StrKey = None
    key7: StrKey = None
    key8: StrKey = None
    key9: StrKey = None
    key10: StrKey = None
    key11: StrKey = None
    key12: StrKey = None
    key13: StrKey = None
    key14: StrKey = None
    key15: StrKey = None
    key16: StrKey = None
    key17: StrKey = None
    key18: StrKey = None
    key19: StrKey = None
    key20: StrKey = None
    search_keys: constr(strict=True, min_length=SEARCH_KEYS_MIN_LEN, max_length=SEARCH_KEYS_MAX_LEN) = None
    range_key1: IntKey = None
    range_key2: IntKey = None
    range_key3: IntKey = None
    range_key4: IntKey = None
    range_key5: IntKey = None
    range_key6: IntKey = None
    range_key7: IntKey = None
    range_key8: IntKey = None
    range_key9: IntKey = None
    range_key10: IntKey = None
    version: IntKey = None

    @validator("*", pre=True)
    def check_dicts_pre(cls, value, values, config, field):
        if not isinstance(value, dict):
            return value

        if len(value) == 0:
            raise ValueError("Filter cannot be empty dict")

        if field.type_.__args__[0] is StrictInt:
            for key in value:
                if key not in INT_OPERATORS:
                    raise ValueError(
                        "Incorrect dict filter. Must contain only the following keys: {}".format(INT_OPERATORS)
                    )
            for operator_group in COMPARISON_GROUPS:
                total_operators_from_group = reduce(
                    lambda agg, operator: agg + 1 if operator in value else agg,
                    operator_group,
                    0,
                )
                if total_operators_from_group > 1:
                    raise ValueError(
                        "Incorrect dict filter. Must contain not more than one key from the following group: {}".format(
                            operator_group
                        )
                    )

        if field.type_.__args__[0] in [StrictStr, MaxLenStr]:
            for key in value:
                if key not in STR_OPERATORS:
                    raise ValueError(f"Incorrect dict filter. Must contain only the following keys: {STR_OPERATORS}")

        return value

    @validator("*")
    def check_dicts(cls, value, values, config, field):
        if not isinstance(value, dict):
            return value

        if len(value) == 0:
            raise ValueError("Filter cannot be empty dict")

        return value

    @validator("search_keys")
    def check_search_keys_without_regular_keys(cls, value, values, config, field):
        non_empty_string_keys = [key for key in values.keys() if values[key] is not None]
        if len(set(SEARCH_KEYS).intersection(set(non_empty_string_keys))) > 0:
            raise ValueError("cannot be used in conjunction with regular key1...key20 lookup")
        return value

    @staticmethod
    def getFindLimit():
        return FIND_LIMIT


class FindFilterNonHashed(FindFilter):
    key1: StrKeyNonHashed = None
    key2: StrKeyNonHashed = None
    key3: StrKeyNonHashed = None
    key4: StrKeyNonHashed = None
    key5: StrKeyNonHashed = None
    key6: StrKeyNonHashed = None
    key7: StrKeyNonHashed = None
    key8: StrKeyNonHashed = None
    key9: StrKeyNonHashed = None
    key10: StrKeyNonHashed = None
    key11: StrKeyNonHashed = None
    key12: StrKeyNonHashed = None
    key13: StrKeyNonHashed = None
    key14: StrKeyNonHashed = None
    key15: StrKeyNonHashed = None
    key16: StrKeyNonHashed = None
    key17: StrKeyNonHashed = None
    key18: StrKeyNonHashed = None
    key19: StrKeyNonHashed = None
    key20: StrKeyNonHashed = None
