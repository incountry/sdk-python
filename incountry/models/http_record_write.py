from pydantic import BaseModel, constr


class HttpRecordWrite(BaseModel):
    body: constr(strict=True, regex="OK")
