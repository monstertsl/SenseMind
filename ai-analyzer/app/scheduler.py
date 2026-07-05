"""定时任务：原始日志清理 / ES 索引清理 / 长期未登录用户禁用

APScheduler 内嵌 FastAPI 进程（单 worker），不引入 Celery。
配置项从 DB 动态读取，每次执行写 system_log 审计。
"""

import logging
import subprocess
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from elasticsearch import Elasticsearch
from sqlalchemy import select

from .config import Config
from .core.database import SessionLocal
from .core.audit import write_system_log
from .db_models.system_config import SystemConfig
from .db_models.user import User
from .db_models.audit_log import LoginLog, SystemLog

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


def _build_admin_es_client() -> Elasticsearch:
    """使用 elastic 超级用户凭据构建 ES 客户端（索引删除需要写权限）。"""
    cfg = Config()
    es_cfg = cfg.elasticsearch
    return Elasticsearch(
        es_cfg["hosts"],
        basic_auth=(es_cfg.get("username", "elastic"), cfg.es_password),
        ca_certs=es_cfg.get("ca_cert"),
        verify_certs=True,
        request_timeout=30,
        headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8"},
    )


def _load_config(db) -> SystemConfig:
    cfg = db.execute(select(SystemConfig).where(SystemConfig.id == 1)).scalar_one_or_none()
    return cfg


def cleanup_raw_logs() -> None:
    """清理 suricata / zeek 原始日志文件（保留 raw_log_retention_days 天）。

    两步走：
    1. 调用 logrotate 按 daily + copytruncate 模式轮转活跃日志：
       - eve.json → eve.json-YYYYMMDD（归档文件 mtime 固定）
       - 原文件被截断为 0 字节，Suricata/Zeek 继续写入，无需重启
    2. find -mtime +N -delete 清理超过保留期的归档文件

    原本只用 find -mtime -delete 对持续追加的活跃文件无效
    （mtime 始终为当前时间），导致 eve.json/conn.log 等无限增长。
    """
    with SessionLocal() as db:
        cfg = _load_config(db)
        days = cfg.raw_log_retention_days if cfg else 7
    cutoff = f"+{days}"

    try:
        # 1. logrotate 轮转（copytruncate 不重启 Suricata/Zeek）
        try:
            result = subprocess.run(
                ["logrotate", "/etc/logrotate.d/sensemind-raw-logs"],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                logger.warning("logrotate 返回非零: %s", result.stderr.strip())
            else:
                logger.info("logrotate 轮转完成")
        except FileNotFoundError:
            logger.error("logrotate 未安装，跳过轮转")
        except Exception as e:
            logger.warning("logrotate 调用失败: %s", e)

        # 2. 清理过期归档（归档文件 mtime 固定，find -mtime 可正确判断）
        #    只清理带日期后缀的归档（eve.json-* / *.log-*），不动活跃文件
        for log_dir in ("/data/suricata/logs", "/data/zeek/logs"):
            try:
                result = subprocess.run(
                    ["find", log_dir, "-type", "f", "(",
                     "-name", "eve.json.*", "-o",
                     "-name", "*.log.*", ")",
                     "-mtime", cutoff, "-delete"],
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode != 0:
                    logger.warning("清理归档 %s 返回非零: %s", log_dir, result.stderr.strip())
            except FileNotFoundError:
                logger.warning("目录不存在，跳过: %s", log_dir)
            except Exception as e:
                logger.warning("清理归档 %s 失败: %s", log_dir, e)

        with SessionLocal() as db:
            write_system_log(
                db, action="cleanup_raw_log",
                target_type="system", target_id="raw-logs",
                detail=f"轮转并清理 {days} 天前原始日志归档（suricata/zeek）",
                operator="scheduler",
            )
        logger.info("原始日志清理完成（保留 %s 天）", days)
    except Exception as e:
        logger.error("原始日志清理任务失败: %s", e, exc_info=True)
        try:
            with SessionLocal() as db:
                write_system_log(
                    db, action="cleanup_raw_log",
                    target_type="system", target_id="raw-logs",
                    detail=f"清理失败: {e}",
                    operator="scheduler",
                )
        except Exception:
            pass


def cleanup_es_indices() -> None:
    """删除超过 es_retention_days 的 soc-YYYY.MM.DD / soc-ai-YYYY.MM.DD 索引。"""
    with SessionLocal() as db:
        cfg = _load_config(db)
        days = cfg.es_retention_days if cfg else 30

    try:
        es = _build_admin_es_client()
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        resp = es.indices.get(index="soc-*,soc-ai-*", expand_wildcards=["open", "closed"])
        to_delete = []
        for index_name in resp.keys():
            # 解析索引名末尾日期：soc-2026.07.02 / soc-ai-2026.07.02
            parts = index_name.rsplit(".", 2)
            if len(parts) < 3:
                continue
            try:
                date_str = ".".join(parts[-2:])
                idx_date = datetime.strptime(date_str, "%Y.%m.%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if idx_date < cutoff:
                to_delete.append(index_name)

        if to_delete:
            es.indices.delete(index=",".join(to_delete), ignore_unavailable=True)

        with SessionLocal() as db:
            write_system_log(
                db, action="cleanup_es_log",
                target_type="system", target_id="es-indices",
                detail=f"删除 {len(to_delete)} 个超过 {days} 天的 ES 索引: {','.join(to_delete[:10])}{'...' if len(to_delete) > 10 else ''}",
                operator="scheduler",
            )
        logger.info("ES 索引清理完成：删除 %d 个（保留 %s 天）", len(to_delete), days)
    except Exception as e:
        logger.error("ES 索引清理任务失败: %s", e, exc_info=True)
        try:
            with SessionLocal() as db:
                write_system_log(
                    db, action="cleanup_es_log",
                    target_type="system", target_id="es-indices",
                    detail=f"清理失败: {e}",
                    operator="scheduler",
                )
        except Exception:
            pass


def deactivate_inactive_users() -> None:
    """禁用长期未登录的非 admin 用户（超过 inactive_days_limit 天）。"""
    with SessionLocal() as db:
        cfg = _load_config(db)
        days = cfg.inactive_days_limit if cfg else 90
    cutoff = datetime.utcnow() - timedelta(days=days)

    try:
        with SessionLocal() as db:
            users_to_disable = db.execute(
                select(User).where(
                    User.is_active == True,  # noqa: E712
                    User.role != "admin",
                    User.last_login_at.is_not(None),
                    User.last_login_at < cutoff,
                )
            ).scalars().all()

            count = 0
            usernames = []
            for user in users_to_disable:
                user.is_active = False
                usernames.append(user.username)
                count += 1
            if count > 0:
                db.commit()

            if count > 0:
                write_system_log(
                    db, action="auto_disable",
                    target_type="user", target_id=",".join(usernames[:10]),
                    detail=f"禁用 {count} 个超过 {days} 天未登录的用户: {','.join(usernames[:5])}{'...' if count > 5 else ''}",
                    operator="scheduler",
                )
            logger.info("未登录用户禁用完成：禁用 %d 个（阈值 %s 天）", count, days)
    except Exception as e:
        logger.error("未登录用户禁用任务失败: %s", e, exc_info=True)
        try:
            with SessionLocal() as db:
                write_system_log(
                    db, action="auto_disable",
                    target_type="system", target_id="users",
                    detail=f"禁用失败: {e}",
                    operator="scheduler",
                )
        except Exception:
            pass


def cleanup_audit_logs() -> None:
    """清理超过 audit_log_retention_days 的登录日志和系统日志。"""
    with SessionLocal() as db:
        cfg = _load_config(db)
        days = cfg.audit_log_retention_days if cfg else 180
    cutoff = datetime.utcnow() - timedelta(days=days)

    try:
        with SessionLocal() as db:
            login_deleted = db.execute(
                LoginLog.__table__.delete().where(LoginLog.created_at < cutoff)
            ).rowcount
            system_deleted = db.execute(
                SystemLog.__table__.delete().where(
                    SystemLog.created_at < cutoff,
                    SystemLog.action != "cleanup_audit_log",
                )
            ).rowcount
            db.commit()
            write_system_log(
                db, action="cleanup_audit_log",
                target_type="system", target_id="audit-logs",
                detail=f"清理 {days} 天前审计日志：登录日志 {login_deleted} 条，系统日志 {system_deleted} 条",
                operator="scheduler",
            )
            logger.info("审计日志清理完成：登录日志 %d 条，系统日志 %d 条（保留 %s 天）",
                        login_deleted, system_deleted, days)
    except Exception as e:
        logger.error("审计日志清理任务失败: %s", e, exc_info=True)
        try:
            with SessionLocal() as db:
                write_system_log(
                    db, action="cleanup_audit_log",
                    target_type="system", target_id="audit-logs",
                    detail=f"清理失败: {e}",
                    operator="scheduler",
                )
        except Exception:
            pass


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
    _scheduler.add_job(cleanup_raw_logs, "cron", hour=2, minute=0, id="cleanup_raw_logs")
    _scheduler.add_job(cleanup_es_indices, "cron", hour=2, minute=30, id="cleanup_es_indices")
    _scheduler.add_job(cleanup_audit_logs, "cron", hour=2, minute=45, id="cleanup_audit_logs")
    _scheduler.add_job(deactivate_inactive_users, "cron", hour=3, minute=0, id="deactivate_inactive_users")
    _scheduler.start()
    logger.info("定时任务已启动（02:00 原始日志 / 02:30 ES索引 / 02:45 审计日志 / 03:00 未登录禁用）")


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("定时任务已停止")
