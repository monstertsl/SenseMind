"""SMTP configuration and test-mail API owned by alert-responder."""

import logging
import os
import re
import smtplib
import ssl
import uuid
from datetime import datetime
from dataclasses import dataclass
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.message import EmailMessage
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

from .security import decrypt_data, encrypt_data

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    password = os.environ.get("ELASTIC_PASSWORD", "")
    DATABASE_URL = f"postgresql+psycopg2://postgres:{password}@postgres:5432/sensemind"

AI_ANALYZER_URL = os.environ.get("AI_ANALYZER_URL", "http://ai-analyzer:9090").rstrip("/")
DEFAULT_SENDER_NAME = "SenseMind安全管理平台"
SMTP_TIMEOUT_SECONDS = 10
EMAIL_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
EMAIL_LOCAL_PART = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5, max_overflow=10, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


class SystemConfig(Base):
    """Mail columns in the existing analyzer-owned system_config table."""

    __tablename__ = "system_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mail_protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    mail_host: Mapped[str] = mapped_column(Text, nullable=False)
    mail_port: Mapped[int] = mapped_column(Integer, nullable=False)
    mail_username: Mapped[str] = mapped_column(Text, nullable=False)
    mail_password: Mapped[str] = mapped_column(Text, nullable=False)
    mail_use_ssl: Mapped[bool] = mapped_column(Boolean, nullable=False)
    mail_sender_name: Mapped[str] = mapped_column(String(100), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, onupdate=datetime.utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_admin(request: Request, response: Response) -> dict:
    authorization = request.headers.get("authorization", "")
    if not authorization:
        raise HTTPException(status_code=401, detail="未提供认证凭据")

    try:
        auth_response = httpx.get(
            f"{AI_ANALYZER_URL}/api/v1/auth/me",
            headers={"Authorization": authorization},
            timeout=5,
        )
    except httpx.HTTPError:
        logger.error("无法连接 analyzer 完成邮件 API 身份校验")
        raise HTTPException(status_code=503, detail="身份校验服务暂不可用") from None

    if auth_response.status_code == 401:
        raise HTTPException(status_code=401, detail="无效或过期的令牌")
    if auth_response.status_code == 403:
        raise HTTPException(status_code=403, detail="账号已被禁用")
    if auth_response.status_code != 200:
        logger.error("analyzer 身份校验返回状态码 %s", auth_response.status_code)
        raise HTTPException(status_code=503, detail="身份校验服务暂不可用")

    user = auth_response.json().get("data") or {}
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")

    refreshed_token = auth_response.headers.get("x-refreshed-token")
    if refreshed_token:
        response.headers["X-Refreshed-Token"] = refreshed_token
        response.headers["Access-Control-Expose-Headers"] = "X-Refreshed-Token"
    return user


def _get_config(db: Session) -> SystemConfig:
    cfg = db.execute(select(SystemConfig).where(SystemConfig.id == 1)).scalar_one_or_none()
    if not cfg:
        raise HTTPException(status_code=503, detail="系统配置尚未初始化")
    return cfg


def _config_response(cfg: SystemConfig) -> dict:
    return {
        "protocol": cfg.mail_protocol or "smtp",
        "host": cfg.mail_host or "",
        "port": cfg.mail_port or 587,
        "username": cfg.mail_username or "",
        "password_configured": bool(cfg.mail_password),
        "use_ssl": bool(cfg.mail_use_ssl),
        "sender_name": cfg.mail_sender_name or DEFAULT_SENDER_NAME,
    }


def _saved_password(cfg: SystemConfig) -> str:
    if not cfg.mail_password:
        return ""
    try:
        return decrypt_data(cfg.mail_password)
    except Exception:
        logger.error("SMTP 密码解密失败，请检查 ENCRYPT_KEY")
        raise HTTPException(status_code=500, detail="SMTP 凭据无法解密，请重新保存邮件配置") from None


def _valid_address(value: str) -> str:
    value = value.strip()
    if "\r" in value or "\n" in value or value.count("@") != 1:
        raise HTTPException(status_code=400, detail="邮箱地址格式无效")
    try:
        address = Address(addr_spec=value)
    except (ValueError, HeaderParseError):
        raise HTTPException(status_code=400, detail="邮箱地址格式无效") from None
    domain_labels = (address.domain or "").split(".")
    if (
        not EMAIL_LOCAL_PART.fullmatch(address.username or "")
        or len(domain_labels) < 2
        or len(domain_labels[-1]) < 2
        or any(not EMAIL_DOMAIN_LABEL.fullmatch(label) for label in domain_labels)
    ):
        raise HTTPException(status_code=400, detail="邮箱地址格式无效")
    return address.addr_spec


@dataclass(frozen=True)
class SMTPSettings:
    protocol: str
    host: str
    port: int
    username: str
    password: str
    use_ssl: bool
    sender_name: str


def _send_configured_email(
    settings: SMTPSettings,
    recipients: list[str],
    subject: str,
    content: str,
    html_content: str | None = None,
) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    sender = _valid_address(settings.username)
    message["From"] = Address(display_name=settings.sender_name or DEFAULT_SENDER_NAME, addr_spec=sender)
    message["To"] = ", ".join(recipients)
    message.set_content(content)
    if html_content:
        message.add_alternative(html_content, subtype="html")

    context = ssl.create_default_context()
    if settings.protocol == "smtps":
        with smtplib.SMTP_SSL(
            settings.host,
            settings.port,
            timeout=SMTP_TIMEOUT_SECONDS,
            context=context,
        ) as client:
            client.login(settings.username, settings.password)
            client.send_message(message)
    else:
        with smtplib.SMTP(settings.host, settings.port, timeout=SMTP_TIMEOUT_SECONDS) as client:
            client.ehlo()
            if settings.use_ssl:
                client.starttls(context=context)
                client.ehlo()
            client.login(settings.username, settings.password)
            client.send_message(message)


def _send_test_mail(settings: SMTPSettings, recipient: str) -> None:
    if not settings.host or not settings.username or not settings.password:
        raise HTTPException(status_code=400, detail="请填写完整的 SMTP 配置")
    if settings.protocol not in {"smtp", "smtps"}:
        raise HTTPException(status_code=400, detail="邮件协议配置无效")
    if settings.protocol == "smtps" and not settings.use_ssl:
        raise HTTPException(status_code=400, detail="SMTPS 协议必须启用 SSL/TLS")

    try:
        _valid_address(settings.username)
    except HTTPException:
        raise HTTPException(status_code=400, detail="SMTP 用户名需使用发件邮箱地址") from None

    try:
        _send_configured_email(
            settings,
            [recipient],
            "SenseMind 邮件配置测试",
            "这是一封 SenseMind 邮件配置测试邮件。若收到此邮件，表示 SMTP 配置可用。",
        )
    except smtplib.SMTPAuthenticationError:
        logger.warning("测试邮件认证失败")
        raise HTTPException(status_code=502, detail="SMTP 认证失败，请检查用户名和密码") from None
    except (smtplib.SMTPConnectError, TimeoutError, OSError):
        logger.warning("测试邮件连接失败")
        raise HTTPException(status_code=502, detail="无法连接邮件服务器，请检查地址、端口和 SSL 设置") from None
    except smtplib.SMTPException as exc:
        logger.warning("测试邮件发送失败，异常类型=%s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="邮件服务器拒绝发送，请检查 SMTP 配置") from None


class MailConfigUpdate(BaseModel):
    protocol: Literal["smtp", "smtps"] = "smtp"
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(default="", max_length=1024)
    use_ssl: bool = True
    sender_name: str = Field(min_length=1, max_length=100)


class TestMailRequest(MailConfigUpdate):
    recipient: str = Field(min_length=3, max_length=320)


app = FastAPI(title="SenseMind Alert Responder", version="1.0.0")


@app.get("/health")
def health():
    return {"status": "ok", "service": "alert-responder"}


@app.get("/api/v1/mail-config")
def get_mail_config(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    cfg = _get_config(db)
    return {"code": 0, "message": "ok", "data": _config_response(cfg), "request_id": str(uuid.uuid4())}


@app.put("/api/v1/mail-config", dependencies=[Depends(require_admin)])
def update_mail_config(
    body: MailConfigUpdate,
    db: Session = Depends(get_db),
):
    host = body.host.strip()
    if not host or any(char in host for char in "\r\n"):
        raise HTTPException(status_code=400, detail="邮件服务器地址不能为空或包含换行符")
    sender_name = body.sender_name.strip()
    if not sender_name or any(char in sender_name for char in "\r\n"):
        raise HTTPException(status_code=400, detail="发件人显示名称不能为空或包含换行符")
    try:
        username = _valid_address(body.username)
    except HTTPException:
        raise HTTPException(status_code=400, detail="SMTP 用户名需使用发件邮箱地址") from None
    if body.protocol == "smtps" and not body.use_ssl:
        raise HTTPException(status_code=400, detail="SMTPS 协议必须启用 SSL/TLS")

    cfg = _get_config(db)
    if not cfg.mail_password and not body.password:
        raise HTTPException(status_code=400, detail="请填写 SMTP 密码")
    cfg.mail_protocol = body.protocol
    cfg.mail_host = host
    cfg.mail_port = body.port
    cfg.mail_username = username
    cfg.mail_use_ssl = body.use_ssl
    cfg.mail_sender_name = sender_name
    if body.password:
        try:
            cfg.mail_password = encrypt_data(body.password)
        except RuntimeError:
            raise HTTPException(status_code=503, detail="服务器未配置邮件凭据加密密钥") from None
    db.commit()
    return {
        "code": 0,
        "message": "邮件配置已保存",
        "data": _config_response(cfg),
        "request_id": str(uuid.uuid4()),
    }


@app.post("/api/v1/mail-config/test")
def send_test_mail(
    body: TestMailRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    recipient = _valid_address(body.recipient)
    host = body.host.strip()
    sender_name = body.sender_name.strip()
    if not host or any(char in host for char in "\r\n"):
        raise HTTPException(status_code=400, detail="邮件服务器地址不能为空或包含换行符")
    if not sender_name or any(char in sender_name for char in "\r\n"):
        raise HTTPException(status_code=400, detail="发件人显示名称不能为空或包含换行符")
    try:
        username = _valid_address(body.username)
    except HTTPException:
        raise HTTPException(status_code=400, detail="SMTP 用户名需使用发件邮箱地址") from None

    cfg = _get_config(db)
    password = body.password or _saved_password(cfg)
    settings = SMTPSettings(
        protocol=body.protocol,
        host=host,
        port=body.port,
        username=username,
        password=password,
        use_ssl=body.use_ssl,
        sender_name=sender_name,
    )
    _send_test_mail(settings, recipient)
    return {"code": 0, "message": "测试邮件已发送", "data": {"status": "sent"}, "request_id": str(uuid.uuid4())}


from . import mail_watches