"""Email notification system using async SMTP."""

from __future__ import annotations

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from src.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Send HTML/plain-text emails via SMTP (Office 365, Gmail, etc.)."""

    async def send(
        self,
        to: str | list[str],
        subject: str,
        html_body: str,
        plain_body: str | None = None,
        cc: list[str] | None = None,
    ) -> bool:
        """Send an email. Returns True on success."""
        if not settings.smtp_host or not settings.smtp_user:
            logger.warning("SMTP not configured — skipping email to %s", to)
            return False

        recipients = [to] if isinstance(to, str) else to
        msg = MIMEMultipart("alternative")
        msg["From"] = settings.smtp_from or settings.smtp_user
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        if cc:
            msg["Cc"] = ", ".join(cc)

        if plain_body:
            msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        all_recipients = recipients + (cc or [])

        try:
            await aiosmtplib.send(
                msg,
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_user,
                password=settings.smtp_password,
                start_tls=True,
                recipients=all_recipients,
            )
            logger.info("Email sent to %s: %s", ", ".join(recipients), subject)
            return True
        except Exception:
            logger.exception("Failed to send email to %s", ", ".join(recipients))
            return False

    async def send_alert_notification(
        self,
        to: str,
        alert_title: str,
        severity: str,
        summary: str,
        alert_id: str,
    ) -> bool:
        """Send an alert notification email."""
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
        }
        color = severity_colors.get(severity, "#6c757d")
        html = f"""
        <html><body style="font-family: Arial, sans-serif; max-width: 600px;">
        <div style="background: {color}; color: white; padding: 16px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">SENTINEL-AI Security Alert</h2>
            <p style="margin: 4px 0 0 0; font-size: 14px;">Severity: {severity.upper()}</p>
        </div>
        <div style="border: 1px solid #ddd; border-top: none; padding: 16px; border-radius: 0 0 8px 8px;">
            <h3>{alert_title}</h3>
            <p>{summary}</p>
            <p style="color: #666; font-size: 12px;">Alert ID: {alert_id}</p>
            <hr>
            <p style="font-size: 12px; color: #999;">
                This is an automated notification from SENTINEL-AI.
                Please check Microsoft Teams for action items.
            </p>
        </div>
        </body></html>
        """
        return await self.send(
            to=to,
            subject=f"[SENTINEL-AI] [{severity.upper()}] {alert_title}",
            html_body=html,
            plain_body=f"[{severity.upper()}] {alert_title}\n\n{summary}\n\nAlert ID: {alert_id}",
        )

    async def send_education_email(
        self,
        to: str,
        user_name: str,
        alert_category: str,
        education_html: str,
        subject: str | None = None,
    ) -> bool:
        """Send a security education email to the affected user."""
        category_display = alert_category.replace("_", " ").title()
        email_subject = subject or f"[SENTINEL-AI] Security Awareness: {category_display}"

        html = f"""
        <html><body style="font-family: Arial, sans-serif; max-width: 700px;">
        <div style="background: #0078d4; color: white; padding: 16px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">Security Awareness Training</h2>
            <p style="margin: 4px 0 0 0; font-size: 14px;">Topic: {category_display}</p>
        </div>
        <div style="border: 1px solid #ddd; border-top: none; padding: 16px; border-radius: 0 0 8px 8px;">
            <p>Hello {user_name},</p>
            <p>A recent security event related to your account has prompted this
               personalized security awareness briefing. Please review the
               following information to help protect yourself and the organization.</p>
            <hr>
            {education_html}
            <hr>
            <p style="font-size: 12px; color: #999;">
                This is an automated security education message from SENTINEL-AI.
                If you have questions, please contact your IT Security team.
            </p>
        </div>
        </body></html>
        """
        return await self.send(to=to, subject=email_subject, html_body=html)
