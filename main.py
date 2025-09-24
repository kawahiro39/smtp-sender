
"""SMTP sending and IMAP webhook API service.

This module exposes a FastAPI application with two endpoints:

* ``POST /smtp`` - Send an email using SMTP credentials supplied in the
  request payload.
* ``POST /imap/webhook`` - Fetch unseen emails from an IMAP mailbox and
  deliver them to a webhook URL.
"""

from __future__ import annotations

import asyncio
import contextlib
import email
from email import policy
from email.message import EmailMessage
from email.utils import make_msgid
import imaplib
import json
import smtplib
from typing import Iterable, List, Optional, Sequence, Union
import urllib.error
import urllib.request

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr, Field, validator


app = FastAPI(title="SMTP Sender", version="1.0.0")


@app.exception_handler(RequestValidationError)
async def handle_request_validation(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return clearer messaging when the JSON payload cannot be parsed."""

    json_errors = [error for error in exc.errors() if error.get("type") == "json_invalid"]
    if json_errors:
        return JSONResponse(
            status_code=400,
            content={
                "detail": (
                    "Invalid JSON payload. Ensure the body is valid JSON with double-quoted "
                    "property names and matches the documented schema."
                )
            },
        )

    return JSONResponse(status_code=422, content={"detail": exc.errors()})

class SMTPSettings(BaseModel):
    host: str = Field(..., description="SMTP server hostname")
    port: int = Field(..., description="SMTP server port")
    username: Optional[str] = Field(
        None, description="Username for SMTP authentication (if required)"
    )
    password: Optional[str] = Field(
        None, description="Password for SMTP authentication (if required)"
    )
    use_tls: bool = Field(
        True, description="Use STARTTLS during SMTP connection (default true)"
    )
    use_ssl: bool = Field(
        False, description="Use SMTP over SSL (SMTPS). Overrides use_tls when true."
    )

    @validator("port")
    def validate_port(cls, value: int) -> int:
        if not (0 < value < 65536):
            raise ValueError("port must be between 1 and 65535")
        return value


def _ensure_list(value: Optional[Iterable[str]]) -> List[str]:
    if value is None:
        return []
    return [item for item in value if item]


class EmailContent(BaseModel):
    sender: EmailStr = Field(..., description="Email address used in From header")
    to: List[EmailStr] = Field(..., description="Primary recipients")
    cc: Optional[List[EmailStr]] = Field(None, description="CC recipients")
    bcc: Optional[List[EmailStr]] = Field(None, description="BCC recipients")
    subject: str = Field("", description="Email subject")
    body: str = Field("", description="Plain text body")
    html_body: Optional[str] = Field(None, description="HTML body (optional)")
    reply_to: Optional[List[EmailStr]] = Field(None, description="Reply-To header")

    @staticmethod
    def _normalize_addresses(
        value: Union[None, EmailStr, Sequence[EmailStr], str]
    ) -> Optional[List[EmailStr]]:
        if value in (None, ""):
            return None

        if isinstance(value, str):
            items = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple, set)):
            items = list(value)
        else:
            items = [value]

        return items or None

    @validator("to", pre=True)
    def validate_to(cls, value: Union[str, Sequence[str]]) -> List[EmailStr]:
        normalized = cls._normalize_addresses(value) or []
        if not normalized:
            raise ValueError("at least one recipient must be provided in 'to'")
        return normalized

    @validator("cc", "bcc", "reply_to", pre=True)
    def validate_optional_recipients(
        cls, value: Union[str, Sequence[str]]
    ) -> Optional[List[EmailStr]]:
        return cls._normalize_addresses(value)


class EmailRequest(BaseModel):
    smtp: SMTPSettings
    mail: EmailContent


class IMAPSettings(BaseModel):
    host: str = Field(..., description="IMAP server hostname")
    port: int = Field(..., description="IMAP server port")
    username: str = Field(..., description="IMAP account username")
    password: str = Field(..., description="IMAP account password")
    use_ssl: bool = Field(True, description="Use SSL/TLS for IMAP connection")

    @validator("port")
    def validate_port(cls, value: int) -> int:
        if not (0 < value < 65536):
            raise ValueError("port must be between 1 and 65535")
        return value


class IMAPWebhookRequest(BaseModel):
    imap: IMAPSettings
    mailbox: str = Field("INBOX", description="Mailbox to check")
    criteria: str = Field(
        "UNSEEN", description="IMAP search criteria (e.g., UNSEEN, ALL, etc.)"
    )
    limit: Optional[int] = Field(
        10,
        description="Maximum number of messages to forward to the webhook (None for all)",
    )
    webhook_url: str = Field(..., description="Endpoint that receives the webhook")


def _prepare_email_message(content: EmailContent) -> EmailMessage:
    message = EmailMessage()
    message["Message-ID"] = make_msgid()
    message["Subject"] = content.subject
    message["From"] = content.sender
    message["To"] = ", ".join(content.to)
    if content.cc:
        message["Cc"] = ", ".join(content.cc)
    if content.reply_to:
        message["Reply-To"] = ", ".join(content.reply_to)

    if content.html_body:
        message.set_content(content.body or "")
        message.add_alternative(content.html_body, subtype="html")
    else:
        message.set_content(content.body or "")

    return message


def _open_smtp_connection(config: SMTPSettings) -> smtplib.SMTP:
    smtp_class = smtplib.SMTP_SSL if config.use_ssl else smtplib.SMTP
    return smtp_class(config.host, config.port, timeout=10)


def _send_email(request: EmailRequest) -> str:
    message = _prepare_email_message(request.mail)
    recipients = (
        _ensure_list(request.mail.to)
        + _ensure_list(request.mail.cc)
        + _ensure_list(request.mail.bcc)
    )

    if not recipients:
        raise ValueError("No recipients provided")

    smtp_config = request.smtp

    try:
        with _open_smtp_connection(smtp_config) as server:
            server.ehlo()

            if smtp_config.use_tls and not smtp_config.use_ssl:
                server.starttls()
                server.ehlo()

            if smtp_config.username and smtp_config.password:
                server.login(smtp_config.username, smtp_config.password)

            server.send_message(
                message, from_addr=request.mail.sender, to_addrs=recipients
            )
        return message["Message-ID"]
    except (smtplib.SMTPException, OSError) as exc:  # pragma: no cover - runtime dependent
        raise HTTPException(status_code=502, detail=f"SMTP error: {exc}") from exc


def _post_webhook(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            # Consume the response to ensure the request completes.
            response.read()
    except urllib.error.URLError as exc:  # pragma: no cover - network dependent
        raise HTTPException(status_code=502, detail=f"Webhook request failed: {exc}") from exc


def _fetch_imap_messages(
    settings: IMAPSettings, mailbox: str, criteria: str
) -> List[tuple[str, EmailMessage]]:
    if settings.use_ssl:
        client = imaplib.IMAP4_SSL(settings.host, settings.port)
    else:
        client = imaplib.IMAP4(settings.host, settings.port)

    with contextlib.ExitStack() as stack:
        stack.callback(lambda: _safe_imap_logout(client))

        try:
            client.login(settings.username, settings.password)
            client.select(mailbox)
            status, data = client.search(None, criteria)
            if status != "OK":
                raise HTTPException(
                    status_code=502, detail=f"IMAP search failed: {status}"
                )

            message_ids = data[0].split()
            messages: List[tuple[str, EmailMessage]] = []
            for message_id in message_ids:
                status, fetched = client.fetch(message_id, "(RFC822)")
                if status != "OK" or not fetched:
                    continue
                raw_email = fetched[0][1]
                email_message = email.message_from_bytes(
                    raw_email, policy=policy.default
                )
                messages.append((message_id.decode("utf-8"), email_message))
            return messages
        except imaplib.IMAP4.error as exc:  # pragma: no cover - runtime dependent
            raise HTTPException(status_code=502, detail=f"IMAP error: {exc}") from exc


def _safe_imap_logout(client: imaplib.IMAP4) -> None:
    try:
        client.logout()
    except imaplib.IMAP4.error:
        pass


@app.post("/smtp")
async def send_email(request: EmailRequest) -> dict:
    """Send an email using the provided SMTP configuration and content."""

    message_id = await asyncio.to_thread(_send_email, request)
    return {"status": "sent", "message_id": message_id}


@app.post("/imap/webhook")
async def trigger_imap_webhook(request: IMAPWebhookRequest) -> dict:
    """Fetch messages from IMAP and forward them to the provided webhook URL."""

    messages = await asyncio.to_thread(
        _fetch_imap_messages, request.imap, request.mailbox, request.criteria
    )

    if request.limit is not None:
        messages = messages[: request.limit]

    for message_id, email_message in messages:
        payload = {
            "message_id": message_id,
            "subject": email_message.get("Subject"),
            "from": email_message.get("From"),
            "to": email_message.get("To"),
            "date": email_message.get("Date"),
            "raw": email_message.as_string(),
        }
        await asyncio.to_thread(_post_webhook, request.webhook_url, payload)

    return {"status": "delivered", "count": len(messages)}

