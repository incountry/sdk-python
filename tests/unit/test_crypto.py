import os
import pytest
import sure  # noqa: F401
import base64

from cryptography.fernet import Fernet

from incountry import InCrypto, InCryptoException, SecretKeyAccessor, StorageClientError

PLAINTEXTS = [
    "",
    "Howdy",  # <-- English
    "Привет медвед",  # <-- Russian
    "مرحبا",  # <-- Arabic
    "हाय",  # <-- Hindi
    "안녕",  # <-- Korean
    "こんにちは",  # Japanese
    "你好",  # <- Chinese
]

PREPARED_DATA_BY_VERSION = {
    "pt": [(("pt:SW5Db3VudHJ5"), "InCountry", "")],
    "1": [
        (
            (
                "1:8b02d29be1521e992b49a9408f2777084e9d8195e4a3392c68c70545eb559670b70ec928c8eeb2e"
                "34f118d32a23d77abdcde38446241efacb71922579d1dcbc23fca62c1f9ec5d97fbc3a9862c0a9e1b"
                "b630aaa3585eac160a65b24a96af5becef3cdc2b29"
            ),
            "InCountry",
            "password",
        )
    ],
    "2": [
        (
            (
                "2:MyAeMDU3wnlWiqooUM4aStpDvW7JKU0oKBQN4WI0Wyl2vSuSmTIu8TY7Z9ljYeaLfg8ti3mhIJhbLS"
                "BNu/AmvMPBZsl6CmSC1KcbZ4kATJQtmZolidyXUGBlXC52xvAnFFGnk2s="
            ),
            "InCountry",
            "password",
        )
    ],
}

VALID_CUSTOM_ENCRYPTION_CONFIG = {
    "encrypt": lambda input, key, key_version: Fernet(key).encrypt(input.encode("utf8")).decode("utf8"),
    "decrypt": lambda input, key, key_version: Fernet(key).decrypt(input.encode("utf8")).decode("utf8"),
    "version": "test",
    "isCurrent": True,
}


@pytest.mark.happy_path
def test_pack_unpack():
    ENC_DATA_LENGTH = 10
    data = os.urandom(ENC_DATA_LENGTH)
    salt = os.urandom(InCrypto.SALT_LENGTH)
    iv = os.urandom(InCrypto.IV_LENGTH)
    auth_tag = os.urandom(InCrypto.AUTH_TAG_LENGTH)

    parts = [salt, iv, data, auth_tag]
    packed = InCrypto.pack_base64(salt, iv, data, auth_tag)
    unpacked = InCrypto.unpack_base64(packed)

    assert all([a == b for a, b in zip(parts, unpacked)])


@pytest.mark.happy_path
def test_unpack_error():
    InCrypto.unpack_base64.when.called_with("").should.have.raised(InCryptoException)


@pytest.mark.parametrize("plaintext", PLAINTEXTS)
@pytest.mark.parametrize("secret_key_accessor", [SecretKeyAccessor(lambda: "password"), None])
@pytest.mark.happy_path
def test_enc_dec(plaintext, secret_key_accessor):
    cipher = InCrypto(secret_key_accessor)

    [enc, *rest] = cipher.encrypt(plaintext)
    dec = cipher.decrypt(enc)

    assert plaintext == dec


@pytest.mark.parametrize("plaintext", PLAINTEXTS)
@pytest.mark.parametrize(
    "secret_key_accessor",
    [
        SecretKeyAccessor(
            lambda: {
                "currentVersion": 2,
                "secrets": [
                    {"secret": "password1", "version": 1},
                    {"secret": "12345678901234567890123456789012", "version": 2, "isKey": True},
                ],
            }
        )
    ],
)
@pytest.mark.happy_path
def test_enc_dec_with_key(plaintext, secret_key_accessor):
    cipher = InCrypto(secret_key_accessor)

    [enc, *rest] = cipher.encrypt(plaintext)
    dec = cipher.decrypt(enc)

    assert plaintext == dec


@pytest.mark.parametrize("plaintext", PLAINTEXTS)
@pytest.mark.happy_path
def test_enc_without_secret_key_accessor(plaintext):
    cipher = InCrypto()

    [enc, version] = cipher.encrypt(plaintext)
    base64.b64decode.when.called_with(enc[len(InCrypto.PT_ENC_VERSION) + 1 :]).should_not.throw(Exception)
    assert version == SecretKeyAccessor.DEFAULT_VERSION


@pytest.mark.parametrize(
    "ciphertext, plaintext, password",
    [data for version_dataset in PREPARED_DATA_BY_VERSION.values() for data in version_dataset],
)
@pytest.mark.happy_path
def test_dec(ciphertext, plaintext, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    cipher = InCrypto(secret_accessor)

    dec = cipher.decrypt(ciphertext)

    assert dec == plaintext


@pytest.mark.happy_path
@pytest.mark.parametrize(
    "secret_key_accessor, expected_version",
    [
        (SecretKeyAccessor(lambda: "password"), SecretKeyAccessor.DEFAULT_VERSION),
        (SecretKeyAccessor(lambda: {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1}]}), 1,),
    ],
)
def test_get_current_version(secret_key_accessor, expected_version):
    cipher = InCrypto(secret_key_accessor=secret_key_accessor)

    assert cipher.get_current_secret_version() == expected_version


@pytest.mark.parametrize(
    "ciphertext, plaintext, password",
    [
        data
        for version, version_dataset in PREPARED_DATA_BY_VERSION.items()
        for data in version_dataset
        if version != "pt"
    ],
)
@pytest.mark.happy_path
def test_dec_non_pt_without_secret_key_accessor(ciphertext, plaintext, password):
    cipher = InCrypto()
    cipher.decrypt.when.called_with(ciphertext).should.have.raised(
        InCryptoException, "No secret_key_accessor provided. Cannot decrypt encrypted data"
    )


@pytest.mark.parametrize("plaintext", PLAINTEXTS)
@pytest.mark.parametrize(
    "custom_encryption", [[VALID_CUSTOM_ENCRYPTION_CONFIG]],
)
@pytest.mark.happy_path
def test_custom_enc_dec(plaintext, custom_encryption):
    key = InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH))

    secret_key_accessor = SecretKeyAccessor(
        lambda: {"currentVersion": 1, "secrets": [{"secret": key, "version": 1, "isForCustomEncryption": True}]}
    )

    cipher = InCrypto(secret_key_accessor, custom_encryption)

    [enc, *rest] = cipher.encrypt(plaintext)
    dec = cipher.decrypt(enc)

    assert plaintext == dec


@pytest.mark.parametrize("plaintext", PLAINTEXTS)
@pytest.mark.parametrize("password", ["password"])
@pytest.mark.error_path
def test_enc_dec_v1_wrong_password(plaintext, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    secret_accessor2 = SecretKeyAccessor(lambda: password + "1")
    cipher = InCrypto(secret_accessor)
    cipher2 = InCrypto(secret_accessor2)

    [enc, *rest] = cipher.encrypt(plaintext)

    cipher2.decrypt.when.called_with(enc).should.have.raised(InCryptoException)


@pytest.mark.parametrize("ciphertext, plaintext, password", PREPARED_DATA_BY_VERSION["pt"])
@pytest.mark.error_path
def test_dec_vPT_no_b64(ciphertext, plaintext, password):
    cipher = InCrypto()

    cipher.decrypt.when.called_with(ciphertext + ":").should.have.raised(InCryptoException)


@pytest.mark.parametrize("ciphertext, plaintext, password", PREPARED_DATA_BY_VERSION["1"])
@pytest.mark.error_path
def test_dec_v1_wrong_auth_tag(ciphertext, plaintext, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    cipher = InCrypto(secret_accessor)

    cipher.decrypt.when.called_with(ciphertext[:-2]).should.have.raised(InCryptoException)


@pytest.mark.parametrize("ciphertext, plaintext, password", PREPARED_DATA_BY_VERSION["2"])
@pytest.mark.error_path
def test_dec_v2_wrong_auth_tag(ciphertext, plaintext, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    cipher = InCrypto(secret_accessor)

    cipher.decrypt.when.called_with(ciphertext[:-2]).should.have.raised(InCryptoException)


@pytest.mark.parametrize(
    "ciphertext", ["unsupported_version:abc", "some:unsupported:data", "7765618db31daf5366a6fc3520010327"]
)
@pytest.mark.error_path
def test_wrong_ciphertext(ciphertext):
    secret_accessor = SecretKeyAccessor(lambda: "password")
    cipher = InCrypto(secret_accessor)

    cipher.decrypt.when.called_with(ciphertext).should.have.raised(InCryptoException)


@pytest.mark.error_path
def test_custom_enc_without_secret_key_accessor():
    InCrypto.when.called_with(None, []).should.have.raised(
        StorageClientError,
        f"provide a valid secret_key_accessor param of class {SecretKeyAccessor.__name__} to use custom encryption",
    )


@pytest.mark.parametrize(
    "custom_encryption",
    [
        [{**VALID_CUSTOM_ENCRYPTION_CONFIG, "decrypt": lambda input, key, key_version: True}],
        [{**VALID_CUSTOM_ENCRYPTION_CONFIG, "encrypt": lambda input, key, key_version: True}],
    ],
)
@pytest.mark.error_path
def test_custom_enc_with_methods_not_returning_str(custom_encryption):
    secret_key_accessor = SecretKeyAccessor(
        lambda: {
            "currentVersion": 1,
            "secrets": [
                {
                    "secret": InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH)),
                    "version": 1,
                    "isForCustomEncryption": True,
                }
            ],
        }
    )

    InCrypto.when.called_with(secret_key_accessor, custom_encryption).should.have.raised(
        StorageClientError, "should return str. Got bool"
    )


@pytest.mark.parametrize(
    "custom_encryption", [[dict(VALID_CUSTOM_ENCRYPTION_CONFIG)]],
)
@pytest.mark.error_path
def test_custom_enc_returning_nonstr_on_enc_after_successful_validation(custom_encryption):
    secret_key_accessor = SecretKeyAccessor(
        lambda: {
            "currentVersion": 1,
            "secrets": [
                {
                    "secret": InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH)),
                    "version": 1,
                    "isForCustomEncryption": True,
                }
            ],
        }
    )

    global i
    i = 0

    def enc(input, key, key_version):
        global i
        if i > 1:
            return True
        i += 1
        return Fernet(key).encrypt(input.encode("utf8")).decode("utf8")

    custom_encryption[0]["encrypt"] = enc
    cipher = InCrypto(secret_key_accessor, custom_encryption)
    cipher.encrypt.when.called_with("plaintext").should.have.raised(
        InCryptoException, "Unexpected error during encryption"
    )


@pytest.mark.parametrize(
    "custom_encryption", [[dict(VALID_CUSTOM_ENCRYPTION_CONFIG)]],
)
@pytest.mark.error_path
def test_custom_enc_returning_nonstr_on_dec_after_successful_validation(custom_encryption):
    secret_key_accessor = SecretKeyAccessor(
        lambda: {
            "currentVersion": 1,
            "secrets": [
                {
                    "secret": InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH)),
                    "version": 1,
                    "isForCustomEncryption": True,
                }
            ],
        }
    )

    global i
    i = 0

    def dec(input, key, key_version):
        global i
        if i > 0:
            return True
        i += 1
        return Fernet(key).decrypt(input.encode("utf8")).decode("utf8")

    custom_encryption[0]["decrypt"] = dec
    cipher = InCrypto(secret_key_accessor, custom_encryption)
    [enc, *rest] = cipher.encrypt("plaintext")
    cipher.decrypt.when.called_with(enc).should.have.raised(InCryptoException, "Unexpected error during decryption")


@pytest.mark.parametrize(
    "custom_encryption", [[dict(VALID_CUSTOM_ENCRYPTION_CONFIG)]],
)
@pytest.mark.error_path
def test_custom_enc_throwing_on_enc_after_successful_validation(custom_encryption):
    secret_key_accessor = SecretKeyAccessor(
        lambda: {
            "currentVersion": 1,
            "secrets": [
                {
                    "secret": InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH)),
                    "version": 1,
                    "isForCustomEncryption": True,
                }
            ],
        }
    )

    global i
    i = 0

    def enc(input, key, key_version):
        global i
        if i > 1:
            raise Exception("error")
        i += 1
        return Fernet(key).encrypt(input.encode("utf8")).decode("utf8")

    custom_encryption[0]["encrypt"] = enc
    cipher = InCrypto(secret_key_accessor, custom_encryption)
    cipher.encrypt.when.called_with("plaintext").should.have.raised(
        InCryptoException, "Unexpected error during encryption"
    )


@pytest.mark.parametrize(
    "custom_encryption", [[dict(VALID_CUSTOM_ENCRYPTION_CONFIG)]],
)
@pytest.mark.error_path
def test_custom_enc_throwing_on_dec_after_successful_validation(custom_encryption):
    secret_key_accessor = SecretKeyAccessor(
        lambda: {
            "currentVersion": 1,
            "secrets": [
                {
                    "secret": InCrypto.b_to_base64(os.urandom(InCrypto.KEY_LENGTH)),
                    "version": 1,
                    "isForCustomEncryption": True,
                }
            ],
        }
    )

    global i
    i = 0

    def dec(input, key, key_version):
        global i
        if i > 0:
            raise Exception("error")
        i += 1
        return Fernet(key).decrypt(input.encode("utf8")).decode("utf8")

    custom_encryption[0]["decrypt"] = dec
    cipher = InCrypto(secret_key_accessor, custom_encryption)
    [enc, *rest] = cipher.encrypt("plaintext")
    cipher.decrypt.when.called_with(enc).should.have.raised(InCryptoException, "Unexpected error during decryption")
