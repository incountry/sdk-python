from pydantic import BaseModel, constr, root_validator


class AttachmentMetaUpdate(BaseModel):
    mime_type: constr(strict=True, min_length=1) = None
    filename: constr(strict=True, min_length=1) = None

    @root_validator
    def validate_anything_is_not_none(cls, values):
        if values.get("mime_type", None) is None and values.get("filename", None) is None:
            raise ValueError(" mime_type/filename - provide at least one valid meta attribute")
        return values
