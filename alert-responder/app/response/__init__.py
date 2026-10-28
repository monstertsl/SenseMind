"""联动处置模块：设备脚本、联动任务、白名单、封堵记录。

与邮件模块（app/main.py、app/mail_watches.py）平级，互不 import。
"""

import logging

from . import registry
from .models import create_response_tables

logger = logging.getLogger(__name__)


def register(app, engine) -> None:
    # 延迟导入，避免 api -> main 的循环导入在模块加载期触发
    from .api import router

    app.include_router(router)

    def _startup() -> None:
        create_response_tables(engine)
        specs = registry.scan(force=True)
        logger.info("联动处置设备脚本已注册：%s", ", ".join(sorted(specs)) or "无")

    app.router.on_startup.append(_startup)
