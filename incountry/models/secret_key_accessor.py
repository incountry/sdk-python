from typing import Callable

from pydantic import BaseModel


class SecretKeyAccessor(BaseModel):
    accessor_function: Callable
