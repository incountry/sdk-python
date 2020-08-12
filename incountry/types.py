from typing import List, Dict, Union

TRecord = Dict[str, Union[str, int]]
TStringFilter = Union[str, List[str], Dict[str, Union[str, List[str]]]]
TIntFilter = Union[int, List[int], Dict[str, Union[int, List[int]]]]
