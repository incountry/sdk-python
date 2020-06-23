from pydantic import BaseModel

from .record_from_server import RecordFromServer


class HttpRecordRead(BaseModel):
    body: RecordFromServer
