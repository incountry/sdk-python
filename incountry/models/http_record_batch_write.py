from pydantic import BaseModel, constr

VALID_BODY = "OK"


class HttpRecordBatchWrite(BaseModel):
    body: constr(strict=True, regex=VALID_BODY)
