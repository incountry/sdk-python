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


class Operators(str):
    NOT = "$not"
    GT = "$gt"
    GTE = "$gte"
    LT = "$lt"
    LTE = "$lte"


FIND_LIMIT = 100

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

NonEmptyStr = constr(min_length=1)
NonEmptyStrList = conlist(StrictStr, min_items=1)
NonEmptyIntList = conlist(StrictInt, min_items=1)
OperatorsStrDict = Dict[NonEmptyStr, Union[StrictStr, NonEmptyStrList]]
OperatorsIntDict = Dict[NonEmptyStr, Union[StrictInt, NonEmptyIntList]]
StrKey = Union[StrictStr, NonEmptyStrList, OperatorsStrDict]
IntKey = Union[StrictInt, NonEmptyIntList, OperatorsIntDict]


class FindFilter(BaseModel):
    limit: conint(ge=1, le=FIND_LIMIT, strict=True) = FIND_LIMIT
    offset: conint(ge=0, strict=True) = 0
    key: StrKey = None
    key2: StrKey = None
    key3: StrKey = None
    profile_key: StrKey = None
    range_key: IntKey = None
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
                    lambda agg, operator: agg + 1 if operator in value else agg, operator_group, 0,
                )
                if total_operators_from_group > 1:
                    raise ValueError(
                        "Incorrect dict filter. Must contain not more than one key from the following group: {}".format(
                            operator_group
                        )
                    )

        if field.type_.__args__[0] is StrictStr:
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

    @staticmethod
    def getFindLimit():
        return FIND_LIMIT
