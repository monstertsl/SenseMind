"""未触发告警的攻击事件检测

从同 community_id 的关联日志中，提取未触发 Suricata alert 的 HTTP 事件，
检测其中是否包含攻击特征（但未被规则覆盖）。

供 Stage 6 反向触发使用：AI 分析一条告警时，顺带检查同会话的非 alert 事件，
为漏报的攻击生成检测规则。

检测分两层：
1. 关键词匹配层（快速，覆盖已知攻击特征）
2. 语义检测层（递归解码 + 语法分析，覆盖编码绕过和变形攻击）
"""

import logging
import os
import re
import html
import base64
import shlex
from urllib.parse import unquote

logger = logging.getLogger(__name__)


# ======================================================================
# 攻击特征关键词（按攻击类型分组）- 第一层：快速关键词匹配
# ======================================================================

ATTACK_PATTERNS = {
    "ognl_injection": [
        "getRuntime", "IOUtils", "opensymphony", "ServletActionContext",
        "ognl", "#a=", "@java", "@org.apache",
    ],
    "ssti": [
        "${", "#{", "*{", "{{",
    ],
    "rce_command_injection": [
        "|echo", "|cat", "|id", "|whoami", "|wget", "|curl",
        ";echo", ";cat", ";id", ";whoami",
        "$(echo", "$(", "system(", "exec(", "passthru(",
    ],
    "webshell_upload": [
        "<?php", "<?=", "eval(", "base64_decode", "assert(",
        "shell_exec", "system(", "passthru(", "unlink(__FILE__)",
    ],
    "file_read_traversal": [
        "/etc/passwd", "/etc/shadow", "..%2f", "%2e%2e",
        "file:///", "file:///etc",
    ],
    "sql_injection": [
        "union select", "union all select", "extractvalue(",
        "updatexml(", "benchmark(", "sleep(", "load_file(",
        "information_schema", "0x7e",
    ],
    "ssrf": [
        "file://", "gopher://", "dict://", "ldap://",
        "169.254.169.254", "metadata.google",
    ],
    "xxe": [
        "<!entity", "<!doctype", "system \"file:",
        "ENTITY disclose", "external entity",
    ],
    "deserialization": [
        "rO0AB", "java.lang.Runtime", "invokertransformer",
        "templatesimpl", "beanfactory",
    ],
    "confluence_ognl": [
        "createpage-entervariables", "queryString=",
    ],
    "druid": [
        "druid/indexer", "firehose", "uris",
    ],
    "spring_spel": [
        "AddResponseHeader", "T(java.lang.Runtime)",
        "T(org.springframework", "copyToByteArray",
    ],
    "log4shell": [
        "${jndi:", "${lower:", "${upper:", "${env:",
        "ldap://", "rmi://", "dns://", "iiop://",
    ],
}


# ======================================================================
# 语义检测配置 - 第二层：递归解码 + 语法分析
# ======================================================================

# 敏感系统文件路径
SENSITIVE_FILES = {
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/self/environ",
    "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
    "/var/log/auth.log", "/var/log/messages",
    "/etc/nginx/nginx.conf", "/etc/httpd/conf/httpd.conf",
    "/etc/my.cnf", "/etc/mysql/my.cnf",
    "/etc/redis/redis.conf", "/etc/mongod.conf",
    "c:/windows/win.ini", "c:/windows/system32/",
    "c:\\windows\\win.ini", "c:\\windows\\system32\\",
}

# 危险 shell 命令（命令注入检测用）
DANGEROUS_COMMANDS = {
    "cat", "ls", "id", "whoami", "uname", "ifconfig", "ip",
    "ping", "nslookup", "dig", "wget", "curl", "nc", "ncat",
    "bash", "sh", "zsh", "python", "python3", "perl", "ruby", "php",
    "powershell", "cmd", "net", "netstat", "ss", "ps", "kill",
    "chmod", "chown", "rm", "mv", "cp", "find", "grep",
    "sudo", "su", "passwd", "useradd", "usermod",
    "iptables", "route", "arp",
    "dd", "mkfs", "fdisk", "mount", "umount",
    "crontab", "at", "systemctl", "service",
    "export", "env", "set", "source",
    "telnet", "ssh", "scp", "rsync",
    "base64", "xxd", "od", "hexdump",
    "mysql", "psql", "redis-cli", "mongo",
    "head", "tail", "more", "less", "tac", "nl",
    "awk", "sed", "tr", "cut", "sort", "uniq",
    "tcpdump", "tshark", "nmap", "masscan",
}

# SQL 危险函数/关键字
SQL_DANGEROUS_FUNCTIONS = {
    "sleep", "benchmark", "load_file", "into outfile",
    "extractvalue", "updatexml", "st_x", "st_fromtext",
    "geometrycollection", "polygon", "linestring",
    "convert", "cast", "char", "ascii", "ord",
    "hex", "unhex", "concat", "group_concat",
    "database", "schema", "version", "user",
    "current_user", "session_user",
    "substring", "substr", "mid", "left", "right",
    "if", "ifnull", "nullif",
}

# SQL 语义检测特征（正则，在清除注释后匹配）
SQL_SEMANTIC_PATTERNS = [
    r"union\s+(all\s+)?select",          # UNION 注入
    r"(and|or)\s+\d+\s*=\s*\d+",         # 布尔注入（数字）
    r"(and|or)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",  # 布尔注入（字符串）
    r"into\s+(outfile|dumpfile)",         # 文件写入
    r"load_file\s*\(",                    # 文件读取
    r"information_schema",                # 信息探测
    r"(select|insert|update|delete|drop|alter|create)\s+",  # SQL 操作
]


# ======================================================================
# 递归解码引擎
# ======================================================================

def recursive_decode(text: str, max_depth: int = 5) -> str:
    """递归解码：反复进行 URL/HTML/Base64/Hex 解码，直到内容不再变化

    解决多层编码绕过问题，例如：
    - %2563%2561%2574 → %63%61%74 → cat（三层 URL 编码）
    - &#99;&#97;&#116; → cat（HTML 实体编码）
    - 0x636174 → cat（Hex 编码）
    """
    if not text:
        return text

    prev = text
    for _ in range(max_depth):
        changed = False

        # URL 解码（+ 也转为空格，符合 URL query string 编码规范）
        try:
            from urllib.parse import unquote_plus
            decoded = unquote_plus(prev)
            if decoded != prev:
                prev = decoded
                changed = True
        except Exception:
            pass

        # HTML 实体解码
        try:
            decoded = html.unescape(prev)
            if decoded != prev:
                prev = decoded
                changed = True
        except Exception:
            pass

        if changed:
            continue

        # Base64 解码（仅对疑似 Base64 的片段）
        stripped = prev.strip()
        if len(stripped) >= 16 and len(stripped) % 4 == 0:
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', stripped):
                try:
                    b64_decoded = base64.b64decode(stripped).decode('utf-8', errors='replace')
                    # 只接受解码后含可打印 ASCII 的结果
                    if b64_decoded and sum(1 for c in b64_decoded if 32 <= ord(c) < 127) > len(b64_decoded) * 0.7:
                        prev = b64_decoded
                        continue
                except Exception:
                    pass

        # Hex 解码（0x 前缀或纯 hex）
        hex_match = re.match(r'^0x([0-9a-fA-F]{6,})$', stripped)
        if hex_match:
            try:
                hex_decoded = bytes.fromhex(hex_match.group(1)).decode('utf-8', errors='replace')
                if hex_decoded:
                    prev = hex_decoded
                    continue
            except Exception:
                pass

        break

    return prev


# ======================================================================
# 语义检测函数
# ======================================================================

def detect_sql_injection_semantic(text: str) -> bool:
    """SQL 注入语义检测

    清除注释绕过后，用正则检测 SQL 注入语义特征：
    - UNION SELECT（含 /**/ 注释绕过）
    - 布尔注入（AND 1=1）
    - 时间盲注（SLEEP/BENCHMARK）
    - 报错注入（EXTRACTVALUE/UPDATEXML）
    - 文件读写（LOAD_FILE/INTO OUTFILE）
    - 信息探测（information_schema/DATABASE）
    """
    if not text:
        return False

    text_lower = text.lower()

    # 清除 SQL 注释（/**/、--、#）
    cleaned = re.sub(r'/\*.*?\*/', '', text_lower)
    cleaned = re.sub(r'--.*$', '', cleaned)
    cleaned = re.sub(r'#.*$', '', cleaned)
    # 清除空白绕过（/**/ 已清除，但可能残留多个空格）
    cleaned = re.sub(r'\s+', ' ', cleaned)

    # 语义特征匹配
    for pattern in SQL_SEMANTIC_PATTERNS:
        if re.search(pattern, cleaned):
            return True

    # 危险函数检测
    for func in SQL_DANGEROUS_FUNCTIONS:
        if f"{func}(" in cleaned:
            return True

    return False


def detect_command_injection_semantic(text: str) -> bool:
    """命令注入语义检测

    清除引号/反斜杠绕过后，解析 shell 命令：
    - 命令分隔符后跟危险命令（; | && || $() ``）
    - 引号绕过（ca''t → cat）
    - 反斜杠绕过（c\\at → cat）
    - 敏感文件路径（/etc/passwd 等）
    """
    if not text:
        return False

    # 清除引号绕过：ca''t → cat, c""at → cat
    # 移除连续的空引号对
    cleaned = re.sub(r"['\"]{2}", '', text)
    # 移除不成对的单个引号（保留成对引号内的内容）
    cleaned = re.sub(r"(?<!\w)['\"]", '', cleaned)

    # 清除反斜杠绕过：c\at → cat
    cleaned = cleaned.replace('\\', '')

    cleaned_lower = cleaned.lower()

    # 检查命令分隔符后的危险命令
    # 分隔符：; | || && & $( ` 换行
    parts = re.split(r'[;|&]|\$\(|`|\n', cleaned_lower)

    for part in parts[1:]:  # 跳过第一部分（可能是正常参数）
        part = part.strip()
        if not part:
            continue

        # 尝试用 shlex 解析命令
        try:
            tokens = shlex.split(part)
        except Exception:
            tokens = part.split()

        if tokens:
            cmd = tokens[0].lower()
            # 去除路径前缀（/bin/cat → cat, /usr/bin/id → id）
            cmd_base = os.path.basename(cmd)
            if cmd_base in DANGEROUS_COMMANDS:
                return True

    # 检查命令替换 $(...) 中的内容
    for subst_match in re.finditer(r'\$\(([^)]+)\)', cleaned_lower):
        subst = subst_match.group(1).strip()
        tokens = subst.split()
        if tokens:
            cmd = os.path.basename(tokens[0].lower())
            if cmd in DANGEROUS_COMMANDS:
                return True

    # 检查敏感文件路径（命令注入常配合文件读取）
    for sensitive_file in SENSITIVE_FILES:
        if sensitive_file in cleaned_lower:
            return True

    return False


def detect_path_traversal_semantic(text: str) -> bool:
    """路径遍历语义检测

    通过路径规范化，检测：
    - ../ 序列（含编码绕过后还原的 ../）
    - 访问敏感系统文件
    - file:// 协议
    """
    if not text:
        return False

    cleaned_lower = text.lower()

    # 检查 file:// 协议
    if 'file://' in cleaned_lower:
        return True

    # 检查 ../ 序列（递归解码后可能还原）
    if '../' in cleaned_lower or '..\\' in cleaned_lower:
        return True

    # 提取路径并规范化检查
    path_patterns = re.findall(
        r'((?:\.\./)+(?:[^/\s"\'<>]*/*)*)|(/[a-zA-Z][^\s"\'<>]*)',
        text
    )
    for path_tuple in path_patterns:
        path = path_tuple[0] or path_tuple[1]
        if not path or len(path) < 3:
            continue
        try:
            normalized = os.path.normpath(path)
            if normalized.startswith('..') or '/../' in normalized:
                return True
        except Exception:
            pass

    # 检查直接访问敏感文件
    for sensitive in SENSITIVE_FILES:
        if sensitive in cleaned_lower:
            return True

    return False


def detect_xss_semantic(text: str) -> bool:
    """XSS 语义检测

    清除编码后检测：
    - <script> 标签
    - 事件处理器（onload=, onerror=）
    - javascript: 协议
    - <svg>、<img>、<iframe> 等危险标签
    """
    if not text:
        return False

    cleaned_lower = text.lower()

    # HTML 标签检测
    xss_patterns = [
        r'<script',
        r'</script',
        r'javascript:',
        r'on(load|error|click|mouseover|focus|blur|submit|change)\s*=',
        r'<svg',
        r'<iframe',
        r'<img[^>]+onerror',
        r'<body[^>]+onload',
        r'document\.cookie',
        r'document\.write',
        r'window\.location',
        r'\.innerhtml',
    ]

    for pattern in xss_patterns:
        if re.search(pattern, cleaned_lower):
            return True

    return False


# ======================================================================
# 事件级检测函数
# ======================================================================


def detect_attack_in_http_event(log: dict) -> list[str]:
    """检测单条 HTTP 事件中是否包含攻击特征

    双层检测：
    1. 关键词匹配层：快速匹配已知攻击特征
    2. 语义检测层：递归解码 + 语法分析，检测编码绕过和变形攻击

    Args:
        log: ES 中的日志文档（Suricata http 事件或 Zeek http 日志）

    Returns:
        命中的攻击类型列表
    """
    # 提取 URL 和 payload
    url = ""
    payload = ""

    # Suricata http 事件
    eve = log.get("suricata", {}).get("eve", {})
    if eve.get("event_type") == "http":
        http = eve.get("http", {})
        url = http.get("url", "")
        payload = eve.get("payload_printable", "")

    # Zeek http 日志
    if not url and log.get("event", {}).get("dataset") == "zeek.http":
        url = log.get("url", {}).get("original", "")
        host = log.get("url", {}).get("domain", "")
        if host and url:
            url = f"{host}{url}"

    # 也检查 event.original（原始 JSON）
    if not url and not payload:
        original = log.get("event", {}).get("original", "")
        if original:
            payload = original

    if not url and not payload:
        return []

    # === 第一层：关键词匹配（快速） ===
    url_decoded = unquote(url) if url else ""
    text_to_check = f"{url_decoded} {payload}".lower()

    matched_types = []
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in text_to_check:
                matched_types.append(attack_type)
                break

    # === 第二层：语义检测（递归解码 + 语法分析） ===
    # 对原始 URL 和 payload 分别递归解码
    raw_text = f"{url} {payload}"
    decoded_text = recursive_decode(raw_text)

    # SQL 注入语义检测
    if "sql_injection" not in matched_types:
        if detect_sql_injection_semantic(decoded_text):
            matched_types.append("sql_injection")

    # 命令注入语义检测
    if "rce_command_injection" not in matched_types:
        if detect_command_injection_semantic(decoded_text):
            matched_types.append("rce_command_injection")

    # 路径遍历语义检测
    if "file_read_traversal" not in matched_types:
        if detect_path_traversal_semantic(decoded_text):
            matched_types.append("file_read_traversal")

    # XSS 语义检测
    if "xss" not in matched_types:
        if detect_xss_semantic(decoded_text):
            matched_types.append("xss")

    return matched_types


def detect_attack_in_dns_event(log: dict) -> list[str]:
    """检测单条 DNS 事件中是否包含攻击特征（DNS 隧道、DGA 等）

    Args:
        log: ES 中的日志文档（Suricata dns 事件或 Zeek dns 日志）

    Returns:
        命中的攻击类型列表
    """
    query = ""

    # Suricata dns 事件
    eve = log.get("suricata", {}).get("eve", {})
    if eve.get("event_type") == "dns":
        dns = eve.get("dns", {})
        query = dns.get("query", "") if isinstance(dns, dict) else ""

    # Zeek dns 日志
    if not query and log.get("event", {}).get("dataset") == "zeek.dns":
        query = log.get("dns", {}).get("question", {}).get("name", "")

    if not query:
        return []

    query_lower = query.lower()
    matched_types = []

    # DNS 隧道检测：超长子域名、TXT 记录异常、Base64 特征
    subdomain = query.split(".")[0] if "." in query else query
    if len(subdomain) > 50:
        matched_types.append("dns_tunneling")

    # 已知恶意域名特征
    dns_threat_patterns = {
        "dns_tunneling": [
            ".dnscat.", "iodine.", "tcpoverdns.",
        ],
        "c2_callback": [
            "update.", "cdn.", "cloudflare-dns.",
        ],
    }

    for attack_type, patterns in dns_threat_patterns.items():
        for pattern in patterns:
            if pattern in query_lower:
                matched_types.append(attack_type)
                break

    return matched_types


def detect_attack_in_ssl_event(log: dict) -> list[str]:
    """检测单条 SSL/TLS 事件中是否包含攻击特征

    Args:
        log: ES 中的日志文档（Suricata tls 事件或 Zeek ssl 日志）

    Returns:
        命中的攻击类型列表
    """
    sni = ""

    # Suricata tls 事件
    eve = log.get("suricata", {}).get("eve", {})
    if eve.get("event_type") == "tls":
        sni = eve.get("tls", {}).get("sni", "")

    # Zeek ssl 日志
    if not sni and log.get("event", {}).get("dataset") == "zeek.ssl":
        sni = log.get("zeek", {}).get("ssl", {}).get("server_name", "")

    if not sni:
        return []

    # 检查可疑的 SNI（如 IP 地址作为 SNI、超长 SNI）
    matched_types = []
    if sni.replace(".", "").isdigit():  # IP 地址作为 SNI
        matched_types.append("suspicious_tls_sni")
    if len(sni) > 100:
        matched_types.append("suspicious_tls_sni")

    return matched_types


def find_unalerted_attacks(related_logs: list) -> list[dict]:
    """从关联日志中找出未触发 alert 的攻击事件

    检查范围：
    - HTTP 事件（Suricata http + Zeek http）
    - DNS 事件（Suricata dns + Zeek dns）
    - SSL/TLS 事件（Suricata tls + Zeek ssl）

    Args:
        related_logs: 同 community_id 的关联日志列表

    Returns:
        未触发 alert 但包含攻击特征的事件列表
        [{"log": log, "attack_types": [...], "url": "...", "payload": "..."}]
    """
    # 收集已触发 alert 的时间戳和 tx_id，避免重复
    alerted_tx_ids = set()
    for log in related_logs:
        eve = log.get("suricata", {}).get("eve", {})
        if eve.get("event_type") == "alert":
            tx_id = eve.get("tx_id")
            if tx_id:
                alerted_tx_ids.add(tx_id)

    unalerted = []
    for log in related_logs:
        eve = log.get("suricata", {}).get("eve", {})
        dataset = log.get("event", {}).get("dataset", "")
        event_type = eve.get("event_type", "")

        # 确定事件类型
        is_http = event_type == "http" or dataset == "zeek.http"
        is_dns = event_type == "dns" or dataset == "zeek.dns"
        is_ssl = event_type == "tls" or dataset == "zeek.ssl"

        if not (is_http or is_dns or is_ssl):
            continue

        # 检查是否已被 alert 覆盖（同 tx_id）
        tx_id = eve.get("tx_id")
        if tx_id and tx_id in alerted_tx_ids:
            continue

        # 根据事件类型调用对应的检测函数
        attack_types = []
        if is_http:
            attack_types = detect_attack_in_http_event(log)
        elif is_dns:
            attack_types = detect_attack_in_dns_event(log)
        elif is_ssl:
            attack_types = detect_attack_in_ssl_event(log)

        if attack_types:
            # 提取事件信息用于规则生成
            url = ""
            payload = ""

            if is_http:
                url = eve.get("http", {}).get("url", "")
                if not url:
                    url = log.get("url", {}).get("original", "")
                payload = eve.get("payload_printable", "")[:500]
            elif is_dns:
                query = ""
                sc_dns = eve.get("dns", {})
                if isinstance(sc_dns, dict):
                    query = sc_dns.get("query", "")
                if not query:
                    query = log.get("dns", {}).get("question", {}).get("name", "")
                url = f"DNS: {query}"
                payload = query
            elif is_ssl:
                sni = eve.get("tls", {}).get("sni", "")
                if not sni:
                    sni = log.get("zeek", {}).get("ssl", {}).get("server_name", "")
                url = f"TLS SNI: {sni}"
                payload = sni

            unalerted.append({
                "attack_types": attack_types,
                "url": url[:200],
                "payload": payload,
                "timestamp": log.get("@timestamp", ""),
                "event_type": "http" if is_http else ("dns" if is_dns else "tls"),
            })
            logger.info(
                "发现未触发告警的攻击事件: types=%s, url=%s",
                attack_types, url[:80],
            )

    return unalerted
