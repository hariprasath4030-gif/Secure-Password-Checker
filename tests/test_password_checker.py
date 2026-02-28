import pytest
from password_checker import check_password_strength


def test_strong_password():
    res = check_password_strength("MyPass123!", min_length=8)
    assert res["strength"] == "Strong"
    assert res["score"] == 5


def test_weak_password():
    res = check_password_strength("abc", min_length=8)
    assert res["strength"] == "Weak"
    assert res["score"] <= 2
    assert "length" in res["failing_rules"]


def test_medium_password():
    res = check_password_strength("Password1", min_length=8)
    # Password1 has length,digit,lowercase,uppercase => score 4 -> Medium
    assert res["strength"] == "Medium"
    assert "special" in res["failing_rules"]


def test_suggestions_include_special():
    res = check_password_strength("Password1", min_length=8)
    assert any("special" in s.lower() for s in res["suggestions"]) or "special" in res["failing_rules"]
