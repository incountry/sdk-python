import pytest
import sure  # noqa: F401


from incountry import SecretKeyAccessor, StorageClientException


INVALID_SECRETS_DATA = [
    [],
    {},
    (),
    False,
    True,
    0,
    1,
    {"secrets": [{"secret": "password", "version": 1}]},
    {"currentVersion": 1},
    {"currentVersion": "1", "secrets": [{"secret": "password", "version": 1}]},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": "1"}]},
    {"currentVersion": 1, "secrets": [{"secret": 1, "version": 1}]},
    {"currentVersion": 1, "secrets": []},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": "yes"}]},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": 1}]},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": 0}]},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": -1}, {"secret": "password", "version": 1}]},
    {"currentVersion": 0, "secrets": [{"secret": "password", "version": 1}]},
]

INVALID_SECRETS_DATA_WITH_SHORT_KEY = [
    *INVALID_SECRETS_DATA,
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": True}]},
]


@pytest.mark.parametrize("password", ["password"])
@pytest.mark.happy_path
def test_get_secret_old(password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    [secret, secret_version, is_key] = secret_accessor.get_secret()
    assert secret == password
    assert secret_version == SecretKeyAccessor.DEFAULT_VERSION
    assert is_key is False


@pytest.mark.parametrize(
    "secrets_data",
    [
        {"currentVersion": 0, "secrets": [{"secret": "password0", "version": 0}]},
        {
            "currentVersion": 1,
            "secrets": [{"secret": "password1", "version": 1}, {"secret": "password2", "version": 2}],
        },
        {
            "currentVersion": 2,
            "secrets": [{"secret": "password1", "version": 1}, {"secret": "password2", "version": 2}],
        },
        {
            "currentVersion": 2,
            "secrets": [
                {"secret": "password1", "version": 1},
                {"secret": "12345678901234567890123456789012", "version": 2, "isKey": True},
            ],
        },
    ],
)
@pytest.mark.happy_path
def test_get_secret(secrets_data):
    secret_accessor = SecretKeyAccessor(lambda: secrets_data)
    [secret, secret_version, is_key] = secret_accessor.get_secret()

    current_secret_data = next(
        (secret for secret in secrets_data["secrets"] if secret["version"] == secrets_data["currentVersion"]),
        None,
    )

    assert secret_version == current_secret_data["version"]
    assert secret == current_secret_data["secret"]
    assert is_key == current_secret_data.get("isKey", False)

    for secret_data in secrets_data["secrets"]:
        [secret, secret_version, is_key] = secret_accessor.get_secret(secret_data["version"])
        assert secret_version == secret_data["version"]
        assert secret == secret_data["secret"]
        assert is_key == secret_data.get("isKey", False)


@pytest.mark.parametrize(
    "secrets_data",
    [
        {"currentVersion": 0, "secrets": [{"secret": "custom key", "version": 0, "isForCustomEncryption": True}]},
        {
            "currentVersion": 1,
            "secrets": [
                {"secret": "custom key", "version": 1, "isForCustomEncryption": True},
                {"secret": "password2", "version": 2},
            ],
        },
        {
            "currentVersion": 2,
            "secrets": [
                {"secret": "custom key", "version": 1, "isForCustomEncryption": True},
                {"secret": "password2", "version": 2},
            ],
        },
        {
            "currentVersion": 2,
            "secrets": [
                {"secret": "password1", "version": 1},
                {"secret": "12345678901234567890123456789012", "version": 2, "isKey": True},
                {"secret": "custom key", "version": 3, "isForCustomEncryption": True},
            ],
        },
    ],
)
@pytest.mark.happy_path
def test_get_secret_with_custom_keys(secrets_data):
    secret_accessor = SecretKeyAccessor(lambda: secrets_data)
    secret_accessor.enable_custom_encryption_keys()
    [secret, secret_version, is_key] = secret_accessor.get_secret()

    current_secret = next(
        (secret for secret in secrets_data["secrets"] if secret["version"] == secrets_data["currentVersion"]),
        None,
    )

    assert secret_version == current_secret["version"]
    assert secret == current_secret["secret"]
    assert is_key == current_secret.get("isKey", False)

    for secret_data in secrets_data["secrets"]:
        [secret, secret_version, is_key] = secret_accessor.get_secret(secret_data["version"])
        assert secret_version == secret_data["version"]
        assert secret == secret_data["secret"]
        assert is_key == secret_data.get("isKey", False)


@pytest.mark.parametrize(
    "secrets_data",
    [{"currentVersion": 0, "secrets": [{"secret": "custom key", "version": 0}]}],
)
@pytest.mark.error_path
def test_get_secret_returning_non_custom_key_for_custom_request(secrets_data):
    secret_accessor = SecretKeyAccessor(lambda: secrets_data)
    secret_accessor.get_secret.when.called_with(is_for_custom_encryption=True).should.have.raised(
        "Requested secret for custom encryption. Got a regular one instead"
    )


@pytest.mark.error_path
def test_non_callable_accessor_function():
    SecretKeyAccessor.when.called_with("password").should.have.raised(StorageClientException)


@pytest.mark.error_path
def test_incorrect_version_requested():
    secret_accessor = SecretKeyAccessor(lambda: "some password")
    secret_accessor.get_secret.when.called_with("non int").should.have.raised(StorageClientException)


@pytest.mark.parametrize("keys_data", [{"currentVersion": 1, "secrets": [{"secret": "password", "version": 1}]}])
@pytest.mark.error_path
def test_non_existing_version_requested(keys_data):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    secret_accessor.get_secret.when.called_with(version=0).should.have.raised(StorageClientException)


@pytest.mark.parametrize(
    "keys_data",
    INVALID_SECRETS_DATA,
)
@pytest.mark.error_path
def test_validation_failure_invalid_keys_object(keys_data):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    secret_accessor.validate.when.called_with().should.have.raised(StorageClientException)


@pytest.mark.error_path
def test_errorful_accessor_function():
    def accessor_function():
        raise Exception("HTTP 500")

    secret_accessor = SecretKeyAccessor(accessor_function)

    secret_accessor.get_secret.when.called_with().should.have.raised(
        StorageClientException, "Failed to retrieve secret keys data"
    )
