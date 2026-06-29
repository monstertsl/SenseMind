"""威胁情报查询客户端

通过配置的 HTTP API 查询 IP/域名的威胁情报。
Triage 判定 need_threat_intel=true 时触发。

配置示例（config.yaml）:
    threat_intel:
      enabled: true
      api_url: "https://api.threatbook.com/v3/scene/ip_reputation"
      api_key_env: "THREAT_INTEL_API_KEY"
      api_key_in: "header"        # header 或 query
      api_key_name: "x-apikey"
      timeout: 10
      jq_filter: ".data | {...}"  # jq 语法提取关键字段，留空返回原始 JSON
"""

import logging
import httpx
from .config import Config

logger = logging.getLogger(__name__)


class ThreatIntelClient:
    """威胁情报查询客户端

    通过 HTTP API 查询 IP/域名的威胁情报，
    支持 header/query 方式传递 API Key，支持 jq 过滤响应。
    """

    def __init__(self):
        cfg = Config()
        ti_cfg = cfg.threat_intel
        self.enabled = ti_cfg.get("enabled", False)
        self.api_url = ti_cfg.get("api_url", "").strip()
        self.api_key = cfg.threat_intel_api_key
        self.api_key_in = ti_cfg.get("api_key_in", "header")
        self.api_key_name = ti_cfg.get("api_key_name", "x-apikey")
        self.timeout = ti_cfg.get("timeout", 10)
        self.jq_filter = ti_cfg.get("jq_filter", "")

        # 延迟加载 jq（可选依赖）
        self._jq_compile = None
        if self.jq_filter:
            try:
                import jq
                self._jq_compile = jq.compile(self.jq_filter)
            except ImportError:
                logger.warning("jq 库未安装，威胁情报响应将不做过滤。安装: pip install jq")
            except Exception as e:
                logger.warning("jq 过滤表达式编译失败: %s", e)

        # 校验配置完整性：enabled=true 但 api_url 为空时自动禁用
        if self.enabled and not self.api_url:
            logger.warning("威胁情报 enabled=true 但 api_url 为空，自动禁用")
            self.enabled = False

        if self.enabled:
            logger.info(
                "威胁情报查询已启用: api=%s, key_in=%s, jq=%s",
                self.api_url, self.api_key_in,
                "启用" if self.jq_filter else "禁用",
            )
        else:
            logger.info("威胁情报查询未启用")

    def query(self, indicator: str, indicator_type: str = "ip") -> dict | None:
        """查询单个 IP 或域名的威胁情报

        Args:
            indicator: IP 地址或域名
            indicator_type: "ip" 或 "domain"

        Returns:
            威胁情报 dict，查询失败返回 None
        """
        if not self.enabled or not self.api_url:
            return None

        if not indicator:
            return None

        # 构造请求
        url = self.api_url
        headers = {"Accept": "application/json"}
        params = {}

        # API Key 传递
        if self.api_key:
            if self.api_key_in == "header":
                headers[self.api_key_name] = self.api_key
            elif self.api_key_in == "query":
                params[self.api_key_name] = self.api_key

        # 查询参数：根据 URL 模板决定传递方式
        if "{type}" in url or "{value}" in url:
            url = url.replace("{type}", indicator_type).replace("{value}", indicator)
        else:
            # 非 URL 模板，通过 query 参数传递
            params["resource"] = indicator

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url, headers=headers, params=params)

            if resp.status_code != 200:
                logger.warning(
                    "威胁情报查询失败: %s=%s, HTTP %d",
                    indicator_type, indicator, resp.status_code,
                )
                return None

            data = resp.json()

            # jq 过滤
            if self._jq_compile:
                try:
                    data = self._jq_compile.input(data)
                    # jq.input 返回生成器，取第一个
                    if hasattr(data, "__iter__") and not isinstance(data, dict):
                        data = next(data, {})
                except Exception as e:
                    logger.warning("jq 过滤失败，返回原始数据: %s", e)

            logger.info(
                "威胁情报查询成功: %s=%s, 结果=%s",
                indicator_type, indicator, str(data)[:200],
            )
            return data

        except Exception as e:
            logger.warning("威胁情报查询异常: %s=%s, %s", indicator_type, indicator, e)
            return None

    def query_for_alert(self, src_ip: str, dst_ip: str,
                        tls_sni: str = "", http_host: str = "") -> str:
        """根据告警上下文查询威胁情报，返回格式化文本

        查询策略：
        1. 优先查询外部 IP（非内网）
        2. 查询 TLS SNI / HTTP Host 域名
        3. 内网 IP 不查询

        Args:
            src_ip: 源 IP
            dst_ip: 目的 IP
            tls_sni: TLS SNI（如有）
            http_host: HTTP Host（如有）

        Returns:
            格式化的威胁情报文本，无结果时返回 "无威胁情报"
        """
        if not self.enabled:
            return "无威胁情报（功能未启用）"

        results = []

        # 内网 IP 段判断
        def is_internal_ip(ip: str) -> bool:
            if not ip:
                return True
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            try:
                first = int(parts[0])
                second = int(parts[1])
                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
                if ip.startswith("127."):
                    return True
                return False
            except ValueError:
                return False

        # 查询外部 IP
        for ip, label in [(src_ip, "源IP"), (dst_ip, "目的IP")]:
            if ip and not is_internal_ip(ip):
                result = self.query(ip, "ip")
                if result:
                    results.append(f"### {label} {ip} 威胁情报\n{result}")

        # 查询域名
        for domain, label in [(tls_sni, "TLS SNI"), (http_host, "HTTP Host")]:
            if domain and not is_internal_ip(domain):
                # 去除端口
                domain_clean = domain.split(":")[0]
                result = self.query(domain_clean, "domain")
                if result:
                    results.append(f"### {label} {domain_clean} 威胁情报\n{result}")

        if not results:
            return "无威胁情报"

        return "\n\n---\n\n".join(results)
