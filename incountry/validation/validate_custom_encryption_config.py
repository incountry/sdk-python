from ..models import CustomEncryptionConfigMethodValidation


def try_custom_encryption_with_key(custom_encryption_config, key, key_version):
    try:
        config_with_key = {**custom_encryption_config, "key": key.encode("utf8"), "keyVersion": key_version}
        CustomEncryptionConfigMethodValidation.validate(config_with_key)
    except Exception as e:
        return (False, e)

    return (True, None)


def validate_custom_encryption_config(config, secrets_data):
    valid_key_found = False
    last_error = None

    if isinstance(secrets_data, tuple):
        [key, key_version, *rest] = secrets_data
        [validation_res, last_error] = try_custom_encryption_with_key(config, key, key_version)
        valid_key_found = valid_key_found or validation_res
    if isinstance(secrets_data, dict):
        for secret_data in secrets_data["secrets"]:
            [validation_res, last_error] = try_custom_encryption_with_key(
                config, secret_data["secret"], secret_data["version"]
            )
            valid_key_found = valid_key_found or validation_res

    if not valid_key_found and last_error is not None:
        raise last_error
