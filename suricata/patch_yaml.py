#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""suricata.yaml 配置补丁 —— 按「段路径」精确定位，幂等，可重复执行。

用法:
    python3 patch_yaml.py [yaml路径] [--check]

安全: 每项校验命中数，不符即整体中止且不落盘。
"""

import re
import sys

DEFAULT_YAML = "/data/suricata/etc/suricata.yaml"

# (op, 段路径, 键/名, 值, 选项)
#   set           键值设置；uncomment 顺带去注释；mode=all 作用于该段下所有同名键
#   comment_out   注释 types 下的列表项，连同其后继子行（直到下一个列表项）
#   delete        删除段下指定键
#   list_replace  列表项改名
#   list_insert   在锚点项后插入（已存在则跳过）
OPS = [
    ("set", ["outputs", "eve-log"], "community-id", "true", {"mode": "all"}),
    ("set", ["outputs", "eve-log", "types", "alert"], "payload-buffer-size", "4 KiB", {"uncomment": True}),
    ("set", ["outputs", "eve-log", "types", "alert"], "payload-printable", "yes", {"uncomment": True}),
    ("set", ["outputs", "eve-log", "types", "alert"], "http-body", "yes", {"uncomment": True}),
    ("set", ["outputs", "eve-log", "types", "alert"], "http-body-printable", "yes", {"uncomment": True}),
    ("set", ["app-layer", "protocols", "http", "libhtp", "default-config"], "http-body-inline", "yes", {}),
    ("delete", ["outputs", "eve-log", "types", "http"], "http-body-printable", None, {}),
    ("comment_out", ["outputs", "eve-log", "types"], "stats", None, {}),
    ("comment_out", ["outputs", "eve-log", "types"], "flow", None, {}),
    ("comment_out", ["outputs", "eve-log", "types"], "mdns", None, {}),
    ("comment_out", ["outputs", "eve-log", "types"], "files", None, {}),
    ("comment_out", ["outputs", "eve-log", "types"], "snmp", None, {}),
    ("comment_out", ["outputs", "eve-log", "types"], "dcerpc", None, {}),
    ("set", ["af-packet"], "interface", "default", {"mode": "all"}),
    ("set", ["af-packet"], "threads", "16", {"mode": "all", "uncomment": True}),
    ("set", ["af-packet"], "ring-size", "65536", {"mode": "all", "uncomment": True}),
    ("set", ["flow"], "memcap", "2 GiB", {}),
    ("set", ["flow"], "hash-size", "4194304", {}),
    ("set", ["flow"], "prealloc", "1000000", {}),
    ("set", ["stream"], "memcap", "4 GiB", {}),
    ("set", ["stream", "reassembly"], "memcap", "8 GiB", {}),
    ("set", ["vlan"], "use-for-tracking", "false", {}),
    ("list_replace", ["rule-files"], "suricata.rules", "combined.rules", {}),
    ("list_insert", ["rule-files"], "combined.rules", "local.rules", {}),
]


def _parse(line):
    """(缩进, 是否注释, 名称, 值)；值 None 表示纯列表项（如 '- flow'）"""
    raw = line.rstrip("\n")
    if not raw.strip():
        return None
    ind = len(raw) - len(raw.lstrip())
    s = raw.strip()
    commented = s.startswith("#")
    if commented:
        # 行首注释（本脚本/sed 加的 `# `）会丢失原缩进，导致后续键的段路径错乱。
        # 用「# 之后内容的实际列号」作为有效缩进，保持层级关系。
        hash_pos = raw.find("#")
        after = raw[hash_pos + 1:]
        ind = hash_pos + 1 + (len(after) - len(after.lstrip()))
        s = after.strip()
    m = re.match(r"^-\s*([A-Za-z0-9_.\-]+):\s*(.*)$", s) or re.match(r"^([A-Za-z0-9_.\-]+):\s*(.*)$", s)
    if m:
        return (ind, commented, m.group(1), m.group(2))
    m2 = re.match(r"^-\s*([A-Za-z0-9_.\-]+)\s*$", s)
    if m2:
        return (ind, commented, m2.group(1), None)
    return None


def _walk(lines):
    stack = []
    for i, line in enumerate(lines):
        p = _parse(line)
        if p is None:
            continue
        ind, commented, name, val = p
        while stack and stack[-1][0] >= ind:
            stack.pop()
        yield (i, [n for _, n in stack], name, val, ind, commented)
        if val is None or val == "":
            stack.append((ind, name))


def locate(lines, path, name):
    return [i for i, sp, nm, val, ind, cm in _walk(lines) if sp == path and nm == name]


def _val_of(lines, i):
    return lines[i].split(":", 1)[1].split("#")[0].strip()


def _commented_exists(lines, name):
    """已被注释掉的同名列表项（幂等判断用）"""
    pat = re.compile(r"^\s*#\s*-\s*%s\b" % re.escape(name))
    return any(pat.match(l) for l in lines)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    check = "--check" in sys.argv
    path = args[0] if args else DEFAULT_YAML

    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    changed = 0
    errors = []

    for op, sec, key, val, opt in OPS:
        label = ".".join(sec) + "." + str(key)

        if op == "set":
            hits = locate(lines, sec, key)
            if not hits or (opt.get("mode") != "all" and len(hits) != 1):
                errors.append("%s 命中 %d 处" % (label, len(hits)))
                continue
            for i in hits:
                raw = lines[i].rstrip("\n")
                is_cmt = raw.lstrip().startswith("#")
                # 注释行不能算「已是目标值」，否则永远不会被去注释
                if not is_cmt and _val_of(lines, i) == val:
                    continue
                if is_cmt and not opt.get("uncomment"):
                    continue
                # 行尾注释要在「去掉行首 # 之后」取，否则会把整行原内容当成注释残留
                body = raw.lstrip()
                if is_cmt:
                    body = body.lstrip("#").lstrip()
                cm = re.search(r"\s+#.*$", body)
                tail = cm.group(0) if cm else ""
                ind = " " * (len(raw) - len(raw.lstrip()))
                dash = "- " if body.startswith("- ") else ""   # 列表项保留 "- " 前缀
                print("  * %-52s -> %s" % (label, val))
                lines[i] = "%s%s%s: %s%s\n" % (ind, dash, key, val, tail)
                changed += 1

        elif op == "delete":
            hits = locate(lines, sec, key)
            if not hits:
                continue
            for i in reversed(hits):
                print("  * %-52s 删除" % label)
                del lines[i]
                changed += 1

        elif op == "comment_out":
            hits = locate(lines, sec, key)
            if len(hits) > 1:
                errors.append("%s 命中 %d 处" % (label, len(hits)))
                continue
            if not hits:
                if _commented_exists(lines, key):
                    continue
                errors.append("%s 未找到（也未注释）" % label)
                continue
            i = hits[0]
            raw = lines[i].rstrip("\n")
            lines[i] = "# " + raw + "\n"   # 与 sed 's/^/# /' 一致：行首加注释
            n = 1
            j = i + 1
            guard = 0
            while j < len(lines) and guard < 30:
                nxt = lines[j].rstrip("\n")
                if not nxt.strip():
                    j += 1
                    continue
                s = nxt.strip()
                if re.match(r"^-\s+\S", s):   # 下一个列表项即停
                    break
                if not s.startswith("#"):
                    lines[j] = "# " + nxt + "\n"
                    n += 1
                j += 1
                guard += 1
            print("  * %-52s 注释（共 %d 行）" % (label, n))
            changed += n

        elif op == "list_replace":
            hits = locate(lines, sec, key)
            if not hits:
                continue
            if len(hits) != 1:
                errors.append("%s 命中 %d 处" % (label, len(hits)))
                continue
            i = hits[0]
            raw = lines[i].rstrip("\n")
            ind = " " * (len(raw) - len(raw.lstrip()))
            lines[i] = "%s- %s\n" % (ind, val)
            print("  * %-52s %s -> %s" % (label, key, val))
            changed += 1

        elif op == "list_insert":
            if locate(lines, sec, val):
                continue
            hits = locate(lines, sec, key)
            if len(hits) != 1:
                errors.append("%s 锚点命中 %d 处" % (label, len(hits)))
                continue
            i = hits[0]
            raw = lines[i].rstrip("\n")
            ind = " " * (len(raw) - len(raw.lstrip()))
            lines.insert(i + 1, "%s- %s\n" % (ind, val))
            print("  * %-52s 插入 %s" % (label, val))
            changed += 1

    if errors:
        for e in errors:
            print("  [错误] " + e)
        print("[-] 未做任何修改，请检查 yaml 结构")
        sys.exit(1)

    if check:
        print("[check] 将修改 %d 处（未写入）" % changed)
        return

    if changed:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        print("[+] 已写入 %d 处修改" % changed)
    else:
        print("[+] 配置均已是目标值，无需修改")


if __name__ == "__main__":
    main()
