"""定时任务：原始日志清理 / ES 索引清理 / 长期未登录用户禁用

APScheduler 内嵌 FastAPI 进程（单 worker），不引入 Celery。
配置项从 DB 动态读取，每次执行写 system_log 审计。
"""

import logging
import os
import re
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
from .db_models.audit_log import SystemLog

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None

# 清理任务在 02:00 Asia/Shanghai 调度，但容器为 UTC；日期类判断须用 UTC+8
# 以对齐用户日历，否则 datetime.now() 取 UTC 会比用户日历晚一天、多留一天。
_SHANGHAI_TZ = timezone(timedelta(hours=8))


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


# logs 目录（/data/suricata/logs、/data/zeek/logs）原始日志固定保留天数。
# 不受 DB 参数控制：存储优化页的"原始日志保留天数"仅作用于 soc-* 索引。
RAW_LOG_FILE_RETENTION_DAYS = 3


def cleanup_raw_logs() -> None:
    """清理 suricata / zeek 原始日志文件（logs 目录固定保留 3 天，不受参数控制）。

    两步走：
    1. 调用 logrotate 按 daily + copytruncate 模式轮转活跃日志：
       - eve.json → eve.json-YYYYMMDD（归档文件名含轮转日期）
       - 原文件被截断为 0 字节，Suricata/Zeek 继续写入，无需重启
    2. 按文件名中的轮转日期（YYYYMMDD）清理超过保留期的归档文件

    说明：归档文件名形如 eve.json-20260716 / conn.log-20260716.gz，
    日期即轮转当天。直接按文件名日期判断是否超过保留期，避免
    find -mtime +N 因归档 mtime 为轮转时刻而多留一天的语义陷阱
    （原实现导致保留 3 天时 16 号归档直到第 5 天才被删）。

    仅当实际清理了归档文件时才记录系统日志（清理 0 条不记录）。
    """
    days = RAW_LOG_FILE_RETENTION_DAYS

    try:
        # 1. logrotate 强制轮转（suricata copytruncate / zeek create+postrotate restart）
        #    -f 强制轮转，不依赖 state 判断"今天是否轮转过"——scheduler 每天只跑一次，
        #    到点即转，逻辑简单可靠。state 文件仍持久化到挂载目录（logrotate 内部需要）。
        logrotate_state = "/data/suricata/logs/.logrotate.status"
        try:
            result = subprocess.run(
                ["logrotate", "-f", "-s", logrotate_state, "/etc/logrotate.d/sensemind-raw-logs"],
                capture_output=True, text=True, timeout=7200,
                env={**os.environ, "TZ": "Asia/Shanghai"},
            )
            if result.returncode != 0:
                logger.warning("logrotate 返回非零: %s", result.stderr.strip())
            else:
                logger.info("logrotate 轮转完成")
        except FileNotFoundError:
            logger.error("logrotate 未安装，跳过轮转")
        except Exception as e:
            logger.warning("logrotate 调用失败: %s", e)

        # 2. 清理过期归档文件
        #    suricata + zeek 统一由 logrotate 轮转，归档名均含 YYYYMMDD
        #    （eve.json-20260724 / conn.log-20260724），按文件名日期统一判断。
        #    cutoff 用 Asia/Shanghai(UTC+8)：任务在 02:00 UTC+8 调度，但容器为 UTC，
        #    datetime.now() 取 UTC 会比用户日历晚一天导致多留一天（7/24 归档在 7/28 才删）。
        date_re = re.compile(r"-(\d{8})")
        cutoff_date = (datetime.now(_SHANGHAI_TZ) - timedelta(days=days)).date()
        deleted_count = 0
        for log_dir in ("/data/suricata/logs", "/data/zeek/logs"):
            if not os.path.isdir(log_dir):
                logger.warning("目录不存在，跳过: %s", log_dir)
                continue
            for name in os.listdir(log_dir):
                path = os.path.join(log_dir, name)
                # 归档文件含日期后缀（YYYYMMDD），活跃文件（无日期后缀）跳过
                m = date_re.search(name)
                if not m:
                    continue
                try:
                    file_date = datetime.strptime(m.group(1), "%Y%m%d").date()
                except ValueError:
                    continue
                if file_date >= cutoff_date:
                    continue
                try:
                    os.remove(path)
                    deleted_count += 1
                    logger.info("删除过期原始日志归档: %s", path)
                except OSError as e:
                    logger.warning("删除失败 %s: %s", path, e)

        # 文件清理成功不写系统日志（仅容器日志），只在失败时写日志
        logger.info("原始日志清理完成：删除 %d 个归档（保留 %s 天）", deleted_count, days)
    except Exception as e:
        logger.error("原始日志清理任务失败: %s", e, exc_info=True)
        try:
            with SessionLocal() as db:
                write_system_log(
                    db, action="cleanup_raw_log",
                    target_type="system", target_id="raw-logs",
                detail=f"清理失败: {e}",
                operator="system",
                )
        except Exception:
            pass


def _cleanup_es_indices(pattern: str, days: int, action: str, log_action: str) -> None:
    """删除超过 days 天的匹配 pattern 的 ES 索引。

    仅当实际删除了索引时才记录系统日志（log_action，清理 0 条不记录）；
    失败时也写系统日志（log_action）以便排障。
    """
    try:
        es = _build_admin_es_client()
        # cutoff = 北京时间"今天 00:00"往前推 (days-1) 天。
        # 语义："保留 days 天" = 保留今天 + 前 (days-1) 天，共 days 个自然日，
        # 删除更早的索引。索引按北京时间日历日生成（logstash soc-%{+YYYY.MM.dd}），
        # 必须用 UTC+8 对齐，且以"当天 00:00"对齐时刻，避免
        # 原实现 now - timedelta(days) 带时刻 + UTC 时区导致多保留 1 天（off-by-one）。
        now_sh = datetime.now(_SHANGHAI_TZ)
        today_sh = now_sh.replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff = today_sh - timedelta(days=days - 1)
        # ignore_unavailable：模式无匹配索引时 ES 返回 404，必须忽略，
        # 否则（如 soc-ai-* 暂无索引）每天任务都会误报失败并写系统日志
        resp = es.indices.get(index=pattern, expand_wildcards=["open", "closed"],
                              ignore_unavailable=True)
        to_delete = []
        for index_name in resp.keys():
            # 索引名格式：soc-2026.07.17 / soc-ai-2026.07.17
            # 以最后一个 "-" 切分，后半段即 "YYYY.MM.DD"
            date_part = index_name.rsplit("-", 1)[-1]
            try:
                # 索引日期即"北京时间当天"，与 cutoff（UTC+8 当天 00:00）同基准比较
                idx_date = datetime.strptime(date_part, "%Y.%m.%d").replace(tzinfo=_SHANGHAI_TZ)
            except ValueError:
                continue
            if idx_date < cutoff:
                to_delete.append(index_name)

        if to_delete:
            es.indices.delete(index=",".join(to_delete), ignore_unavailable=True)
            # 仅当实际删除了索引时才记录系统日志（清理 0 条不记录）
            with SessionLocal() as db:
                write_system_log(
                    db, action=log_action,
                    target_type="system", target_id="es-indices",
                    detail=f"{action}：删除 {len(to_delete)} 个超过 {days} 天的索引: "
                           f"{','.join(to_delete[:10])}{'...' if len(to_delete) > 10 else ''}",
                    operator="system",
                )
        logger.info("%s 索引清理完成：删除 %d 个（保留 %s 天）", action, len(to_delete), days)
    except Exception as e:
        logger.error("%s 索引清理任务失败: %s", action, e, exc_info=True)
        try:
            with SessionLocal() as db:
                write_system_log(
                    db, action=log_action,
                    target_type="system", target_id="es-indices",
                    detail=f"{action} 清理失败: {e}",
                    operator="system",
                )
        except Exception:
            pass


def cleanup_raw_es_indices() -> None:
    """删除超过 raw_log_retention_days 的 soc-YYYY.MM.DD 原始日志索引。

    pattern 用 "soc-*,-soc-ai-*"：ES 通配符 soc-* 会匹配 soc-ai-*，
    须用 "-" 排除语法将分析日志索引排除，避免被原始日志策略误删。
    """
    with SessionLocal() as db:
        cfg = _load_config(db)
        days = cfg.raw_log_retention_days if cfg else 7
    _cleanup_es_indices("soc-*,-soc-ai-*", days, "soc-* 原始日志", "cleanup_raw_es_log")


def cleanup_ai_es_indices() -> None:
    """删除超过 ai_retention_days 的 soc-ai-YYYY.MM.DD 分析日志索引。"""
    with SessionLocal() as db:
        cfg = _load_config(db)
        days = cfg.ai_retention_days if cfg else 180
    _cleanup_es_indices("soc-ai-*", days, "soc-ai-* 分析日志", "cleanup_ai_es_log")


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
                    operator="system",
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
                operator="system",
                )
        except Exception:
            pass


def cleanup_audit_logs() -> None:
    """清理超过 audit_log_retention_days 的系统日志（含登录记录）。"""
    with SessionLocal() as db:
        cfg = _load_config(db)
        days = cfg.audit_log_retention_days if cfg else 180
    cutoff = datetime.utcnow() - timedelta(days=days)

    try:
        with SessionLocal() as db:
            system_deleted = db.execute(
                SystemLog.__table__.delete().where(
                    SystemLog.created_at < cutoff,
                    SystemLog.action != "cleanup_audit_log",
                )
            ).rowcount
            db.commit()
            # 仅当实际清理了日志时才记录（清理 0 条不记录）
            if system_deleted > 0:
                write_system_log(
                    db, action="cleanup_audit_log",
                    target_type="system", target_id="audit-logs",
                    detail=f"清理 {days} 天前系统日志 {system_deleted} 条",
                    operator="system",
                )
            logger.info("审计日志清理完成：系统日志 %d 条（保留 %s 天）",
                        system_deleted, days)
    except Exception as e:
        logger.error("审计日志清理任务失败: %s", e, exc_info=True)
        try:
            with SessionLocal() as db:
                write_system_log(
                    db, action="cleanup_audit_log",
                    target_type="system", target_id="audit-logs",
                    detail=f"清理失败: {e}",
                    operator="system",
                )
        except Exception:
            pass


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
    _scheduler.add_job(cleanup_raw_logs, "cron", hour=2, minute=0, id="cleanup_raw_logs")
    _scheduler.add_job(cleanup_raw_es_indices, "cron", hour=2, minute=30, id="cleanup_raw_es_indices")
    _scheduler.add_job(cleanup_ai_es_indices, "cron", hour=2, minute=32, id="cleanup_ai_es_indices")
    _scheduler.add_job(cleanup_audit_logs, "cron", hour=2, minute=45, id="cleanup_audit_logs")
    _scheduler.add_job(deactivate_inactive_users, "cron", hour=3, minute=0, id="deactivate_inactive_users")
    _scheduler.start()
    logger.info("定时任务已启动（02:00 原始日志 / 02:30 soc索引 / 02:32 soc-ai索引 / 02:45 审计日志 / 03:00 未登录禁用）")


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("定时任务已停止")
