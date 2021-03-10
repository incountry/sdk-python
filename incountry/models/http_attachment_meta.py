from pydantic import BaseModel

from .attachment_meta import AttachmentMeta


class HttpAttachmentMeta(BaseModel):
    body: AttachmentMeta
