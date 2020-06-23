from pydantic import BaseModel, constr


class HttpRecordBatchWrite(BaseModel):
    body: constr(strict=True, regex="OK")
