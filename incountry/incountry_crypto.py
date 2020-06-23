import hashlib
import os
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .exceptions import StorageCryptoException
from .secret_key_accessor import SecretKeyAccessor
from .validation import validate_model
from .models import InCrypto as InCryptoModel


class InCrypto:
    SALT_LENGTH = 64  # Bytes
    IV_LENGTH = 12  # Bytes
    AUTH_TAG_LENGTH = 16  # Bytes
    PBKDF2_ROUNDS = 10000
    KEY_LENGTH = 32  # Bytes
    PBKDF2_DIGEST = "sha512"

    ENC_VERSION = "2"
    PT_ENC_VERSION = "pt"
    CUSTOM_ENCRYPTION_VERSION_PREFIX = "c"

    SUPPORTED_VERSIONS = ["pt", "1", "2"]

    @validate_model(InCryptoModel)
    def __init__(self, secret_key_accessor=None, custom_encryption_configs=None):
        self.secret_key_accessor = secret_key_accessor
        self.custom_encryption_configs = None
        self.custom_encryption_version = None

        if custom_encryption_configs is not None:
            self._init_custom_encryption(custom_encryption_configs)

    def _init_custom_encryption(self, configs):
        version_to_use = next((c["version"] for c in configs if c.get("isCurrent", False) is True), None)

        configs_by_packed_version = {}
        for c in configs:
            version = InCrypto.pack_custom_encryption_version(c["version"])
            configs_by_packed_version[version] = c

        self.custom_encryption_configs = configs_by_packed_version
        if version_to_use is not None:
            self.custom_encryption_version = InCrypto.pack_custom_encryption_version(version_to_use)

    def _get_decryptor(self, enc_version):
        if enc_version == self.PT_ENC_VERSION:
            return self.decrypt_pt
        if self.secret_key_accessor is None:
            raise StorageCryptoException("No secret_key_accessor provided. Cannot decrypt encrypted data")
        if enc_version == "1":
            return self.decrypt_v1
        if enc_version == "2":
            return self.decrypt_v2

        if self.custom_encryption_configs is not None and enc_version in self.custom_encryption_configs:
            return self.decrypt_custom

        raise StorageCryptoException("Unknown decryptor version requested")

    def encrypt(self, raw):
        try:
            if self.custom_encryption_version is None:
                return self.encrypt_default(raw)

            return self.encrypt_custom(raw)
        except Exception as e:
            raise StorageCryptoException("Unexpected error during encryption") from e

    def encrypt_custom(self, raw):
        try:
            [key, key_version] = self.get_key(is_for_custom_encryption=True)
            custom_encryption = self.custom_encryption_configs[self.custom_encryption_version]
            encrypted = custom_encryption["encrypt"](input=raw, key=key, key_version=key_version)
        except Exception as e:
            raise StorageCryptoException("Unexpected error during custom encryption 'encrypt'") from e

        if not isinstance(encrypted, str):
            raise StorageCryptoException(
                "Custom encryption 'encrypt' method should return string. Got " + str(type(encrypted))
            )

        return (
            self.custom_encryption_version + ":" + InCrypto.str_to_base64(encrypted),
            key_version,
        )

    def encrypt_default(self, raw):
        if self.secret_key_accessor is None:
            return [
                InCrypto.PT_ENC_VERSION + ":" + InCrypto.str_to_base64(raw),
                SecretKeyAccessor.DEFAULT_VERSION,
            ]

        salt = os.urandom(InCrypto.SALT_LENGTH)
        iv = os.urandom(InCrypto.IV_LENGTH)
        [key, key_version, *rest] = self.get_key(salt)

        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        encrypted = encryptor.update(raw.encode("utf8")) + encryptor.finalize()
        auth_tag = encryptor.tag
        return (
            InCrypto.ENC_VERSION + ":" + self.pack_base64(salt, iv, encrypted, auth_tag),
            key_version,
        )

    def decrypt(self, enc, key_version=None):
        parts = enc.split(":")

        if len(parts) != 2:
            raise StorageCryptoException("Invalid ciphertext")

        [enc_version, packed_enc] = parts

        decryptor = self._get_decryptor(enc_version)

        try:
            return decryptor(packed_enc, key_version=key_version, enc_version=enc_version)
        except Exception as e:
            raise StorageCryptoException("Unexpected error during decryption") from e

    def decrypt_pt(self, enc, key_version=None, enc_version=None):
        return base64.b64decode(enc).decode("utf8")

    def decrypt_custom(self, enc, key_version, enc_version):
        try:
            [key, *rest] = self.get_key(key_version=key_version, is_for_custom_encryption=True)
            raw_enc = InCrypto.base64_to_str(enc)
            decrypted = self.custom_encryption_configs[enc_version]["decrypt"](
                input=raw_enc, key=key, key_version=key_version
            )
        except Exception as e:
            raise StorageCryptoException("Unexpected error during custom encryption 'decrypt'") from e

        if not isinstance(decrypted, str):
            raise StorageCryptoException(
                "Custom encryption 'decrypt' method should return string. Got " + str(type(decrypted))
            )

        return decrypted

    def decrypt_v1(self, packed_enc, key_version, enc_version):
        b_data = bytes.fromhex(packed_enc)
        min_len = InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH + InCrypto.AUTH_TAG_LENGTH

        if len(b_data) < min_len:
            raise StorageCryptoException("Wrong ciphertext size")

        [salt, iv, enc, auth_tag] = [
            b_data[: InCrypto.SALT_LENGTH],
            b_data[InCrypto.SALT_LENGTH : InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH],
            b_data[InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH : len(b_data) - InCrypto.AUTH_TAG_LENGTH],
            b_data[-InCrypto.AUTH_TAG_LENGTH :],
        ]

        [key, *rest] = self.get_key(salt, key_version=key_version)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend()).decryptor()
        return (decryptor.update(enc) + decryptor.finalize()).decode("utf8")

    def decrypt_v2(self, packed_enc, key_version, enc_version):
        [salt, iv, enc, auth_tag] = self.unpack_base64(packed_enc)
        [key, *rest] = self.get_key(salt, key_version=key_version)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend()).decryptor()
        return (decryptor.update(enc) + decryptor.finalize()).decode("utf8")

    def get_key(self, salt=b"", key_version=None, is_for_custom_encryption=False):
        [secret, version, is_key] = self.secret_key_accessor.get_secret(
            version=key_version, is_for_custom_encryption=is_for_custom_encryption
        )

        if is_key or is_for_custom_encryption:
            return (secret.encode("utf8"), version)

        return (
            hashlib.pbkdf2_hmac(
                InCrypto.PBKDF2_DIGEST, secret.encode("utf8"), salt, InCrypto.PBKDF2_ROUNDS, InCrypto.KEY_LENGTH,
            ),
            version,
        )

    def get_current_secret_version(self):
        [secret, version, is_key] = self.secret_key_accessor.get_secret()
        return version

    @staticmethod
    def b_to_base64(bytes):
        return base64.b64encode(bytes).decode("utf8")

    @staticmethod
    def str_to_base64(enc):
        return base64.b64encode(enc.encode("utf8")).decode("utf8")

    @staticmethod
    def base64_to_str(enc):
        return base64.b64decode(enc).decode("utf8")

    @staticmethod
    def pack_custom_encryption_version(version):
        return InCrypto.CUSTOM_ENCRYPTION_VERSION_PREFIX + base64.b64encode(version.encode("utf8")).decode("utf8")

    @staticmethod
    def pack_base64(salt, iv, enc, auth_tag):
        parts = [salt, iv, enc, auth_tag]
        joined_parts = b"".join(parts)
        return base64.b64encode(joined_parts).decode("utf8")

    @staticmethod
    def unpack_base64(enc):
        b_data = base64.b64decode(enc)
        min_len = InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH + InCrypto.AUTH_TAG_LENGTH
        if len(b_data) < min_len:
            raise StorageCryptoException("Wrong ciphertext size")
        return [
            b_data[: InCrypto.SALT_LENGTH],
            b_data[InCrypto.SALT_LENGTH : InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH],
            b_data[InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH : len(b_data) - InCrypto.AUTH_TAG_LENGTH],
            b_data[-InCrypto.AUTH_TAG_LENGTH :],
        ]
