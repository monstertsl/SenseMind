# SOC重点安全检测分类（Suricata + Elastic + AI分析）

==================================================
01 Web应用攻击（Web Attack）
==================================================

SQL注入（SQL Injection）

命令执行 / 代码执行 / 远程代码执行（Command Injection / Code Injection / RCE）

XML外部实体注入（XXE）

服务端模板注入（SSTI）

表达式注入（OGNL / SpEL / EL Injection）

LDAP注入

NoSQL注入

文件上传（含Webshell上传）

任意文件读取

目录遍历（Path Traversal）

任意文件下载

文件包含（LFI / RFI）

任意文件写入

恶意文件执行

Webshell利用

Webshell管理工具通信
（冰蝎 / 蚁剑 / 哥斯拉 / 菜刀）

动态脚本执行

异常HTTP POST通信

非授权访问

权限绕过

水平越权（IDOR）

垂直越权

管理员接口暴露


==================================================
02 身份认证攻击（Authentication Attack）
==================================================

登录页面爆破

SSH暴力破解

RDP暴力破解

FTP暴力破解

数据库暴力破解
（MySQL / MSSQL / Redis / Oracle等）

VPN登录爆破

弱口令尝试

默认账号密码尝试

撞库攻击（Credential Stuffing）

账号枚举

Session攻击

Cookie攻击

JWT Token攻击

MFA绕过


==================================================
03 扫描探测行为（Reconnaissance）
==================================================

主机扫描

端口扫描

Nmap扫描

Masscan扫描

服务探测（Service Discovery）

Banner信息获取

Web爬虫行为

目录扫描

敏感路径扫描

漏洞扫描器特征流量

Burp Suite扫描

Nessus扫描

Nuclei扫描

AWVS扫描

POC探测行为


==================================================
04 漏洞利用攻击（Exploit）
==================================================

Struts2框架漏洞利用

Log4j漏洞利用

Spring框架漏洞利用

Spring Cloud漏洞利用

ThinkPHP漏洞利用

Fastjson漏洞利用

Shiro漏洞利用

Jackson反序列化漏洞利用

Java反序列化攻击

PHP反序列化攻击

Apache漏洞利用

Nginx漏洞利用

Tomcat漏洞利用

WebLogic漏洞利用

VPN设备漏洞利用


==================================================
05 恶意通信与C2（Command And Control）
==================================================

C2通信行为

木马通信

远控通信

Beacon心跳

周期性回连

DGA域名检测

恶意域名通信

Fast Flux域名

域名前置通信

Tor通信

代理通信

加密隧道通信

TLS异常通信

JA3/JA4异常指纹

恶意软件下载

Payload下载

Loader通信


==================================================
06 横向移动（Lateral Movement）
==================================================

SMB横向移动

RDP横向移动

WMI横向移动

SSH横向移动

WinRM横向移动

PsExec远程执行

远程服务创建

Pass The Hash

Pass The Ticket

Kerberos攻击

域内横向访问


==================================================
07 数据泄露与外传（Data Exfiltration）
==================================================

大量异常上传

敏感数据外泄

异常HTTP上传

HTTPS大流量上传

FTP数据外传

云存储上传

数据库导出

数据库Dump

文件批量下载

压缩打包行为

ZIP文件外传

RAR文件外传

7Z文件外传


==================================================
08 隧道通信（Tunnel）
==================================================

DNS隧道

ICMP隧道

HTTP Tunnel

HTTPS Tunnel

SSH Tunnel

WebSocket Tunnel

代理转发


==================================================
09 DDoS攻击
==================================================

TCP Flood

SYN Flood

ACK Flood

UDP Flood

ICMP Flood

DNS Flood

HTTP Flood

HTTPS Flood

CC攻击

Slow HTTP攻击


==================================================
10 主机攻击（Host Attack）
==================================================

主机持久化行为

计划任务持久化

Windows服务创建

注册表Run键启动

启动项修改

WMI永久事件

Linux Cron任务

SSH Key植入


权限提升（Privilege Escalation）

Linux提权

Windows提权

内核漏洞提权

Sudo提权


凭据窃取（Credential Dumping）

LSASS Dump

SAM数据库读取

浏览器密码窃取

SSH Key窃取

Token窃取


==================================================
11 命令与脚本执行（Execution）
==================================================

PowerShell攻击

CMD异常执行

Linux Shell执行

恶意脚本执行

Python脚本执行

JavaScript脚本执行

宏执行

Office恶意宏

文件落地执行


==================================================
12 LOLBin攻击
==================================================

PowerShell

cmd.exe

certutil.exe

bitsadmin.exe

mshta.exe

rundll32.exe

regsvr32.exe

wmic.exe

installutil.exe


==================================================
13 信息泄露（Information Disclosure）
==================================================

.git目录泄露

.svn目录泄露

.env文件泄露

配置文件泄露

源码泄露

备份文件泄露

数据库备份泄露

日志文件泄露

密钥泄露

AccessKey泄露

Token泄露

密码泄露


==================================================
14 恶意文件与木马行为（Malware）
==================================================

恶意软件下载

木马下载

病毒文件传播

Dropper行为

Loader行为

恶意DLL加载

恶意脚本

勒索软件通信

远控工具通信


==================================================
15 攻击链关联分析（AI重点）
==================================================

漏洞扫描

↓

漏洞利用尝试

↓

漏洞利用成功

↓

权限获取

↓

Webshell植入

↓

C2通信

↓

横向移动

↓

数据外泄


==================================================
16 AI上下文分析字段
==================================================

attack.category

attack.technique

attack.stage

severity

confidence

src_ip

dst_ip

src_port

dst_port

protocol

http_uri

http_method

payload

user_agent

domain

file_hash

asset

host

related_events

mitre_attack_id

first_seen

last_seen


==================================================
17 推荐MITRE ATT&CK映射
==================================================

Initial Access

Execution

Persistence

Privilege Escalation

Defense Evasion

Credential Access

Discovery

Lateral Movement

Collection

Command and Control

Exfiltration

Impact