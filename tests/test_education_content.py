"""Tests for education content library."""

from src.core.models import AlertCategory
from src.education.content import get_education_html, get_category_topics


def test_get_category_topics_phishing():
    topics = get_category_topics(AlertCategory.PHISHING)
    assert "recognizing_phishing_emails" in topics
    assert "safe_link_practices" in topics


def test_get_category_topics_unknown():
    topics = get_category_topics(AlertCategory.SUSPICIOUS_ACTIVITY)
    assert "general_security_awareness" in topics


def test_get_education_html_returns_content():
    html = get_education_html(["recognizing_phishing_emails"])
    assert "Recognize Phishing" in html or "phishing" in html.lower()
    assert "<li>" in html


def test_get_education_html_multiple_topics():
    html = get_education_html([
        "recognizing_phishing_emails",
        "strong_password_practices",
    ])
    assert "phishing" in html.lower()
    assert "password" in html.lower()


def test_get_education_html_unknown_topic():
    html = get_education_html(["nonexistent_topic"])
    assert "contact your security team" in html.lower()
