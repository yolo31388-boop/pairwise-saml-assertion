import pytest

from security.saml_assertion import (
    verify_assertion,
    check_signature_wrapping,
    recipient_ok,
    time_window_ok,
    replay_cache
)


def test_valid():
    a = {'issuer': 'idp', 'audience': 'sp', 'recipient': 'https://sp/acs', 'in_response_to': 'r1', 'not_before': 90, 'not_on_or_after': 110, 'signature': True}
    assert verify_assertion(a, 'r1', 'idp', 'sp', 100) is True

def test_audience():
    a = {'issuer': 'idp', 'audience': 'other', 'recipient': 'https://sp/acs', 'in_response_to': 'r1', 'not_before': 90, 'not_on_or_after': 110, 'signature': True}
    assert verify_assertion(a, 'r1', 'idp', 'sp', 100) is False

def test_issuer():
    a = {'issuer': 'evil', 'audience': 'sp', 'recipient': 'https://sp/acs', 'in_response_to': 'r1', 'not_before': 90, 'not_on_or_after': 110, 'signature': True}
    assert verify_assertion(a, 'r1', 'idp', 'sp', 100) is False

def test_recipient():
    assert recipient_ok({'recipient': 'https://sp/acs'}, 'https://sp/acs') is True

def test_recipient_bad():
    assert recipient_ok({'recipient': 'https://other/acs'}, 'https://sp/acs') is False

def test_expired():
    assert time_window_ok({'not_before': 90, 'not_on_or_after': 95}, 100) is False

def test_not_before():
    assert time_window_ok({'not_before': 105, 'not_on_or_after': 110}, 100) is False

def test_in_response():
    a = {'issuer': 'idp', 'audience': 'sp', 'recipient': 'https://sp/acs', 'in_response_to': 'r2', 'not_before': 90, 'not_on_or_after': 110, 'signature': True}
    assert verify_assertion(a, 'r1', 'idp', 'sp', 100) is False

def test_wrapping():
    assert check_signature_wrapping({'wrapped': True}) is True

def test_no_signature():
    a = {'issuer': 'idp', 'audience': 'sp', 'recipient': 'https://sp/acs', 'in_response_to': 'r1', 'not_before': 90, 'not_on_or_after': 110}
    assert verify_assertion(a, 'r1', 'idp', 'sp', 100) is False

def test_replay_first():
    cache = {}
    assert replay_cache(cache, 'a1') is True

def test_replay_second():
    cache = {}
    assert replay_cache(cache, 'a1') is True
    assert replay_cache(cache, 'a1') is False

def test_skew():
    assert time_window_ok({'not_before': 90, 'not_on_or_after': 95}, 100, 10) is True

def test_empty():
    assert verify_assertion({}, 'r1', 'idp', 'sp', 100) is False

def test_window_end():
    assert time_window_ok({'not_before': 90, 'not_on_or_after': 100}, 100) is True
