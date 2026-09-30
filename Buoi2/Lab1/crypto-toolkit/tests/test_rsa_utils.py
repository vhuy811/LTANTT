import pytest

from securecrypto import rsa_utils


def test_generate_keypair():
    priv, pub = rsa_utils.generate_rsa_keypair(2048)
    assert priv.key_size == 2048
    assert pub.public_numbers().e == 65537


def test_reject_weak_key_size():
    with pytest.raises(ValueError):
        rsa_utils.generate_rsa_keypair(1024)


def test_sign_and_verify():
    priv, pub = rsa_utils.generate_rsa_keypair()
    data = b"Hop dong so 01/UEF"
    sig = rsa_utils.sign_data_rsa(data, priv)
    assert rsa_utils.verify_signature_rsa(data, sig, pub) is True


def test_verify_tampered_data():
    priv, pub = rsa_utils.generate_rsa_keypair()
    sig = rsa_utils.sign_data_rsa(b"chuyen 100.000 VND", priv)
    assert rsa_utils.verify_signature_rsa(b"chuyen 900.000 VND", sig, pub) is False


def test_verify_with_other_public_key():
    priv, _ = rsa_utils.generate_rsa_keypair()
    _, other_pub = rsa_utils.generate_rsa_keypair()
    sig = rsa_utils.sign_data_rsa(b"data", priv)
    assert rsa_utils.verify_signature_rsa(b"data", sig, other_pub) is False
