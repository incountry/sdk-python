from io import BufferedIOBase
from typing import Union
from pydantic import BaseModel, constr, StrictBool, validator, FilePath

MAX_BODY_LENGTH = 100 * 1024 * 1024  # 100 Mb
ATTACHMENT_TOO_LARGE_ERROR_MESSAGE = (
    f"Validation failed during Storage.add_attachment(). "
    f"Attachment is too large. Max allowed attachment size is {MAX_BODY_LENGTH} bytes"
)


class AttachmentCreate(BaseModel):
    file: Union[BufferedIOBase, FilePath]
    record_key: constr(strict=True, min_length=1)
    mime_type: constr(strict=True, min_length=1) = None
    upsert: StrictBool = False

    @validator("file")
    def filepath_to_file(cls, value):
        if not isinstance(value, BufferedIOBase):
            return open(str(value), "rb")
        return value

    class Config:
        arbitrary_types_allowed = True
