import base64
import boto3
import json

from incountry import SecretKeyAccessor, Storage

COUNTRY_CODE = "us"
CLIENT_ID = "INCOUNTRY_CLIENT_ID"
CLIENT_SECRET = "INCOUNTRY_CLIENT_SECRET"
ENVIRONMENT_ID = "INCOUNTRY_ENVIRONMENT_ID"

AWS_IAM_ACCESS_KEY_ID = "AWS_IAM_ACCESS_KEY_ID"
AWS_IAM_SECRET_ACCESS_KEY = "AWS_IAM_SECRET_ACCESS_KEY"

AWS_KMS_REGION = "us-east-1"
# For the details about CMK see
# https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html#create-symmetric-cmk
AWS_KMS_MASTER_KEY_ID_ARN = "AWS_KMS_MASTER_KEY_ID_ARN"
AWS_KMS_ENCRYPTED_KEY_BASE64 = "AWS_KMS_ENCRYPTED_KEY_BASE64"


def run():
    kms = boto3.client(
        "kms",
        aws_access_key_id=AWS_IAM_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_IAM_SECRET_ACCESS_KEY,
        region_name=AWS_KMS_REGION,
    )

    ciphertext_blob = base64.b64decode(AWS_KMS_ENCRYPTED_KEY_BASE64)

    response = kms.decrypt(
        CiphertextBlob=ciphertext_blob,
        KeyId=AWS_KMS_MASTER_KEY_ID_ARN,
    )

    if not response or not response["Plaintext"] or not isinstance(response["Plaintext"], bytes):
        return

    decrypted_key = response["Plaintext"]

    decoded_key = base64.b64encode(decrypted_key).decode("utf8")

    secrets = {
        "currentVersion": 1,
        "secrets": [{"secret": decoded_key, "version": 1, "is_key": True}],
    }

    storage = Storage(
        environment_id=ENVIRONMENT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        secret_key_accessor=SecretKeyAccessor(lambda: secrets),
    )

    new_record = {
        "record_key": "recordKey-testAWSKMSKeys",
        "key1": "key1",
        "key2": "key2",
        "key3": "key3",
        "key10": "key10",
        "profile_key": "profileKey",
        "range_key1": 125,
        "body": json.dumps({"test": "Test AWS KMS keys in Python SDK"}),
    }

    storage.write(country=COUNTRY_CODE, **new_record)

    storage.delete(country=COUNTRY_CODE, record_key=new_record["record_key"])


run()
