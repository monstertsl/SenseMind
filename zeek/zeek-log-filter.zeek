# SenseMind Zeek 日志过滤脚本
# 保留 conn + http 日志；dns / ssl / packet_filter 不再输出。
# 本脚本随 zeek 启动命令加载（未经过 site/local.zeek）。
#
# 实现：
#   1. 运行时遍历 Log::active_streams 反向保留（priority=-10），禁用基础协议流
#   2. PacketFilter::LOG 在 zeek_init &priority=5 创建（晚于 -10），且第一条记录在
#      zeek_init 期间就写入，disable_stream 来不及。改用 hook PacketFilter::log_policy
#      直接 break 否决所有写入，从根本上阻止 packet_filter.log 产生。
#   注：zeek priority 数值越小越先执行。

# Zeek 日志轮转统一由 logrotate 管理（create 模式 + postrotate docker restart zeek）。
redef LogAscii::enable_leftover_log_rotation = T;

module SenseMindFilter;

# 保留的日志流：conn（全流量记录）+ http（联合查询语义分析）
const keep_streams: set[Log::ID] = {
    Conn::LOG,
    HTTP::LOG,
};

# 禁用基础协议流（在默认 priority 的 zeek_init 之后执行）
event zeek_init() &priority=-10
    {
    # 先收集待禁用的流，再统一禁用；避免在遍历 active_streams 的同时
    # disable_stream 修改该表引发迭代器失效（iterator invalidation）。
    local to_disable: set[Log::ID] = set();
    for ( sid in Log::active_streams )
        {
        if ( sid !in keep_streams )
            add to_disable[sid];
        }
    for ( sid in to_disable )
        Log::disable_stream(sid);
    }

# PacketFilter::LOG 在 zeek_init &priority=5 创建，第一条记录在 install() 里立即写入，
# disable_stream（即使 priority=10）来不及拦截。直接 hook 其 log_policy 用 break 否决。
hook PacketFilter::log_policy(rec: PacketFilter::Info, id: Log::ID, filter: Log::Filter)
    {
    break;
    }

# 减少 conn.log 体积：写盘前剔除与 SOC 分析冗余或纯噪音的连接。
const conn_noise_ports: set[port] = {
    53/udp, 53/tcp,
    5355/udp, 5353/udp, 1900/udp,
    137/udp, 138/udp, 139/tcp,
    123/udp, 67/udp, 68/udp,
};

# Zeek 8.2 移除 filter$invalidate 字段，改用 break 否决该记录写入。
hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
    {
    if ( ! rec?$id ) return;
    if ( rec$id$resp_p in conn_noise_ports )
        break;
    if ( rec$id$resp_h in 224.0.0.0/4 )
        break;
    }

