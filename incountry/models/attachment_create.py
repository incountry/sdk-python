import os
from io import BufferedIOBase
from typing import Union
from pydantic import BaseModel, constr, StrictBool, validator, FilePath

MAX_BODY_LENGTH = 100 * 1024 * 1024  # 100 Mb
ATTACHMENT_TOO_LARGE_ERROR_MESSAGE = f"Attachment is too large. Max allowed attachment size is {MAX_BODY_LENGTH} bytes"


class AttachmentCreate(BaseModel):
    file: Union[BufferedIOBase, FilePath]
    record_key: constr(strict=True, min_length=1)
    mime_type: constr(strict=True, min_length=1) = None
    upsert: StrictBool = False

    @validator("file")
    def filepath_to_file(cls, value):
        prepared_file = value
        if not isinstance(value, BufferedIOBase):
            prepared_file = open(str(value), "rb")

        file_size = 0
        if prepared_file.seekable():
            position = prepared_file.tell()
            prepared_file.seek(0, os.SEEK_END)
            file_size = prepared_file.tell()
            prepared_file.seek(position, os.SEEK_SET)

        if file_size > MAX_BODY_LENGTH:
            raise ValueError(ATTACHMENT_TOO_LARGE_ERROR_MESSAGE)

        return prepared_file

    class Config:
        arbitrary_types_allowed = True
