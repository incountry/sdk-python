from datetime import datetime

from pydantic import BaseModel, conint, constr


class AttachmentMeta(BaseModel):
    created_at: datetime
    updated_at: datetime
    download_link: constr(strict=True, min_length=1)
    file_id: constr(strict=True, min_length=1)
    filename: constr(strict=True, min_length=1)
    hash: constr(strict=True, min_length=64, max_length=64)
    mime_type: constr(strict=True, min_length=1)
    size: conint(strict=True, ge=0)
