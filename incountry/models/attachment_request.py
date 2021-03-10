from pydantic import BaseModel, constr


class AttachmentRequest(BaseModel):
    record_key: constr(strict=True, min_length=1)
    file_id: constr(strict=True, min_length=1)
