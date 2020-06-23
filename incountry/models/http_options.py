from pydantic import BaseModel, conint

DEFAULT_HTTP_TIMEOUT_SECONDS = 30


class HttpOptions(BaseModel):
    timeout: conint(strict=True, gt=0) = DEFAULT_HTTP_TIMEOUT_SECONDS
