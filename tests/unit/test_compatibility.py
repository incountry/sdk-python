import pytest
import sure  # noqa: F401


from incountry import InCrypto, SecretKeyAccessor, decrypt_record, encrypt_record


from .utils import omit


PREPARED_PAYLOAD = [
    {
        "record_key": "InCountryKey",
        "key2": "InCountryKey2",
        "key3": "InCountryKey3",
        "profile_key": "InCountryPK",
        "body": '{"data": "InCountryBody"}',
        "range_key1": 100500,
    },
    "InCountry",
    "password",
]

STORED_RECORDS = [
    {
        "key": "976143aa1fd12b9ad7449fd9d3a6d25347d71b890b49d4fb5c738e798238865f",
        "body": f"2:IGJNCmV+RXZydaPxDjjhZ80/6aZ2vcEUZ2GuOzKgVSSdM6gYf5RPgFbyLqv+7ihz0CpYFQQWf9xkIyD/u3VYky8"
        f"dWLq+NXcE2xYL4/U7LqUZmJPQzgcQCABYQ/8vOvUEcrfOAwzGjR6etTp1ki+79JmCEZFSNqcDP1GZXNLFdLoSUp1X2wVlH9uk"
        f"hJ4jrE0cKDrpJllswRSOz0BhS8PA/73KNKwo718t7fPWpUm7RkyILwYTd/LpPvpXMS6JypEns8fviOpbCLQPpZNBe6zpwbFf3"
        f"C0qElHlbCyPbDyUiMzVKOwWlYFpozFcRyWegjJ42T8v52+GuRY5",
        "key2": "abcb2ad9e9e0b1787f262b014f517ad1136f868e7a015b1d5aa545b2f575640d",
        "key3": "1102ae53e55f0ce1d802cc8bb66397e7ea749fd8d05bd2d4d0f697cedaf138e3",
        "profile_key": "f5b5ae4914972ace070fa51b410789324abe063dbe2bb09801410d9ab54bf833",
        "range_key": 100500,
        "version": 0,
    },
    {
        "record_key": "976143aa1fd12b9ad7449fd9d3a6d25347d71b890b49d4fb5c738e798238865f",
        "body": f"2:IGJNCmV+RXZydaPxDjjhZ80/6aZ2vcEUZ2GuOzKgVSSdM6gYf5RPgFbyLqv+7ihz0CpYFQQWf9xkIyD/u3VYky8"
        f"dWLq+NXcE2xYL4/U7LqUZmJPQzgcQCABYQ/8vOvUEcrfOAwzGjR6etTp1ki+79JmCEZFSNqcDP1GZXNLFdLoSUp1X2wVlH9uk"
        f"hJ4jrE0cKDrpJllswRSOz0BhS8PA/73KNKwo718t7fPWpUm7RkyILwYTd/LpPvpXMS6JypEns8fviOpbCLQPpZNBe6zpwbFf3"
        f"C0qElHlbCyPbDyUiMzVKOwWlYFpozFcRyWegjJ42T8v52+GuRY5",
        "key2": "abcb2ad9e9e0b1787f262b014f517ad1136f868e7a015b1d5aa545b2f575640d",
        "key3": "1102ae53e55f0ce1d802cc8bb66397e7ea749fd8d05bd2d4d0f697cedaf138e3",
        "profile_key": "f5b5ae4914972ace070fa51b410789324abe063dbe2bb09801410d9ab54bf833",
        "range_key1": 100500,
        "version": 0,
    },
]


@pytest.mark.parametrize(
    "stored_record", STORED_RECORDS,
)
@pytest.mark.parametrize(
    "expected_record, env_id, password", [PREPARED_PAYLOAD],
)
@pytest.mark.happy_path
def test_dec_stored_data(stored_record, expected_record, env_id, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    cipher = InCrypto(secret_accessor)

    decrypted_record = decrypt_record(cipher, stored_record)

    assert omit(decrypted_record, "version", "is_encrypted") == expected_record


@pytest.mark.parametrize(
    "stored_record", [STORED_RECORDS[1]],
)
@pytest.mark.parametrize(
    "expected_record, env_id, password", [PREPARED_PAYLOAD],
)
@pytest.mark.happy_path
def test_enc_data(stored_record, expected_record, env_id, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    cipher = InCrypto(secret_accessor)

    encrypted_record = encrypt_record(cipher, expected_record, env_id)

    assert omit(encrypted_record, "body", "is_encrypted") == omit(stored_record, "body")
