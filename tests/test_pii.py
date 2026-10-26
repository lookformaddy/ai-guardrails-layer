from guardrails.pii import detect_pii, redact


def kinds(text):
    return [f.kind for f in detect_pii(text)]


def test_email_detected():
    assert "pii.email" in kinds("Reach jordan.lee@example.org today.")


def test_phone_detected():
    assert "pii.phone" in kinds("Call (415) 555-0132 tomorrow.")


def test_ssn_detected():
    assert "pii.ssn" in kinds("SSN on file: 123-45-6789.")


def test_credit_card_luhn_valid():
    assert "pii.credit_card" in kinds("Card: 4111 1111 1111 1111.")


def test_digit_runs_not_cards():
    # Order numbers and dates must not trip the card detector.
    assert "pii.credit_card" not in kinds("Order 482913 shipped 2026-03-04.")
    assert "pii.ssn" not in kinds("Order 482913 shipped 2026-03-04.")


def test_api_key_and_secret_detected():
    found = kinds("api_key: sk-testkey1234567890abcdef and password: 'hunter2!'")
    assert "pii.api_key" in found
    assert "pii.secret" in found


def test_private_key_header_detected():
    assert "pii.private_key" in kinds("-----BEGIN PRIVATE KEY-----")


def test_benign_text_clean():
    assert detect_pii("Summarize the quarterly report for review.") == []


def test_redact_replaces_spans_with_tokens():
    text = "Email jordan.lee@example.org or call (415) 555-0132."
    findings = detect_pii(text)
    out = redact(text, findings)
    assert "jordan.lee@example.org" not in out
    assert "(415) 555-0132" not in out
    assert "[REDACTED:EMAIL]" in out
    assert "[REDACTED:PHONE]" in out
    assert out.startswith("Email ")


def test_redact_restricted_to_kinds():
    text = "Email jordan.lee@example.org, call (415) 555-0132."
    findings = detect_pii(text)
    out = redact(text, findings, kinds={"pii.email"})
    assert "[REDACTED:EMAIL]" in out
    assert "(415) 555-0132" in out
