from typing import List, Dict, Union

TRecord = Dict[str, Union[str, int]]
TStringFilter = Union[str, List[str], None, Dict[str, Union[str, List[str], None]]]
TIntFilter = Union[int, List[int], None, Dict[str, Union[int, List[int], None]]]
