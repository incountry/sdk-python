from inspect import getfullargspec
from functools import reduce


def function_args_to_kwargs(function, args, kwargs):
    func_args = getfullargspec(function)[0]
    if "self" in func_args:
        func_args = func_args[1:]
    kwargs.update(dict(zip(func_args, args)))


def format_loc(error_loc_data, extra_path=None):
    if extra_path is not None:
        error_loc_data = (extra_path,) + error_loc_data
    if len(error_loc_data) == 1:
        if error_loc_data[0] == "__root__":
            return ""
        return error_loc_data[0] + " - "
    return (
        error_loc_data[0]
        + "".join(map(lambda idx: "[{}]".format(idx if isinstance(idx, int) else f"'{idx}'"), list(error_loc_data)[1:]))
        + " - "
    )


def get_formatted_validation_error(e, prefix="", path=None):
    return reduce(
        (lambda agg, error: f"{agg}\n  {prefix}{format_loc(error['loc'], path)}{error['msg']}"), e.errors(), ""
    )
