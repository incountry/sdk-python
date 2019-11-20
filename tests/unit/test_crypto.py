import os
import pytest
import sure


from incountry import InCrypto, InCryptoException, SecretKeyAccessor

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
    "0": [(("7765618db31daf5366a6fc3520010327"), "InCountry", "password")],
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

PREPARED_HASH = {
    "hash": "e3937cd968975a95dfd22424ac9370c1e1239d97cc23a2310b807bdd8b1c7a9f",
    "plaintext": "InCountry",
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
@pytest.mark.parametrize("password", ["password"])
@pytest.mark.happy_path
def test_enc_dec(plaintext, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    cipher = InCrypto(secret_accessor)

    [enc, *rest] = cipher.encrypt(plaintext)
    dec = cipher.decrypt(enc)

    assert plaintext == dec


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
def test_hash():
    cipher = InCrypto("password")

    assert PREPARED_HASH["hash"] == cipher.hash(PREPARED_HASH["plaintext"])


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


@pytest.mark.parametrize("ciphertext, plaintext, password", PREPARED_DATA_BY_VERSION["0"])
@pytest.mark.error_path
def test_dec_v0_wrong_padding(ciphertext, plaintext, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    cipher = InCrypto(secret_accessor)

    cipher.decrypt.when.called_with(ciphertext[:-2]).should.have.raised(InCryptoException)


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


@pytest.mark.parametrize("ciphertext", ["unsupported_version:abc", "some:unsupported:data"])
@pytest.mark.error_path
def test_wrong_ciphertext(ciphertext):
    secret_accessor = SecretKeyAccessor(lambda: "password")
    cipher = InCrypto(secret_accessor)

    cipher.decrypt.when.called_with(ciphertext).should.have.raised(InCryptoException)


@pytest.mark.error_path
def test_no_secret_key_accessor():
    InCrypto.when.called_with().should.have.raised(TypeError)
