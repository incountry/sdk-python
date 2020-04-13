import pytest
import sure  # noqa: F401
from pydantic import BaseModel, StrictInt, StrictStr, validator

from incountry import StorageClientError, StorageError
from incountry.validation import validate_model, validate_encryption_enabled

POPAPI_URL = "https://popapi.com:8082"
COUNTRY = "us"


@pytest.mark.happy_path
def test_validate_model_decorator_properly_transforms_data_with_or_without_named_args():
    class TestModel(BaseModel):
        arg1: str = None
        arg2: int = None
        arg3: bool = None
        arg4: str = None

        @validator("arg1", always=True)
        def validate_and_replace_arg1(cls, value):
            return "arg1"

        @validator("arg2", always=True)
        def validate_and_replace_arg2(cls, value):
            return 100

        @validator("arg3", always=True)
        def validate_and_replace_arg3(cls, value):
            return True

    test_kwargs = {"arg1": "random_str", "arg2": 123, "arg3": False, "arg4": "test", "arg5": "arg5"}

    validated_data = TestModel(
        arg1=test_kwargs["arg1"], arg2=test_kwargs["arg2"], arg3=test_kwargs["arg3"], arg4=test_kwargs["arg4"]
    )

    @validate_model(TestModel)
    def test_function(arg1=None, arg2=None, arg3=None, arg4=None, arg5=None):
        assert validated_data.arg1 == arg1
        assert validated_data.arg2 == arg2
        assert validated_data.arg3 == arg3
        assert validated_data.arg4 == arg4
        assert test_kwargs["arg5"] == arg5

    test_function(**test_kwargs)
    test_function(
        test_kwargs["arg1"], test_kwargs["arg2"], test_kwargs["arg3"], test_kwargs["arg4"], test_kwargs["arg5"]
    )


@pytest.mark.error_path
def test_validate_model_properly_throws_validation_error():
    class TestModel(BaseModel):
        arg1: StrictStr = None
        arg2: StrictInt = None

    @validate_model(TestModel)
    def test_function(arg1=None, arg2=None):
        raise Exception("this code should not be reached during the test")

    test_function.when.called_with(arg1=123, arg2="123").should.throw(StorageClientError)


@pytest.mark.happy_path
def test_validate_encryption_enabled_works_properly():
    class TestClass:
        def __init__(self, encrypt=True):
            self.encrypt = encrypt

        @validate_encryption_enabled
        def test_method(self):
            return "test"

    instance1 = TestClass(encrypt=True)
    instance1.test_method.when.called_with().should_not.throw(StorageClientError)

    instance2 = TestClass(encrypt=False)
    instance2.test_method.when.called_with().should.throw(StorageClientError)


@pytest.mark.error_path
def test_validate_model_catches_method_errors():
    error_text = "unexpected_exception"

    class TestModel(BaseModel):
        arg1: StrictStr = None

    def test_function(arg1=None, arg2=None):
        raise Exception(error_text)

    validate_model(TestModel)(test_function).when.called_with(arg1="123").should.throw(StorageError, "Unexpected error")
