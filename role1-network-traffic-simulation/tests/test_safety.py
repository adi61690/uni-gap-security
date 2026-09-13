from app.safety import validate_private_ip, validate_limit
import pytest

def test_private_allowed():
    assert validate_private_ip("10.1.2.3") == "10.1.2.3"

def test_public_rejected():
    with pytest.raises(ValueError): validate_private_ip("8.8.8.8")

def test_limit():
    assert validate_limit(10,100,"x")==10
    with pytest.raises(ValueError): validate_limit(101,100,"x")
