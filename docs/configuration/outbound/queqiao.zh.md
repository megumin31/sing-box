# 鹊桥（Queqiao）

实验性原生 Queqiao protocol 1 出站，支持 TCP 与基本 UDP 代理。

```json
{
  "type": "queqiao",
  "tag": "queqiao-out",
  "profile_path": "/etc/sing-box/queqiao-profile.json",
  "transport": "tcp",
  "network": ["tcp", "udp"]
}
```

## 字段

### profile_path

**必填。** 官方鹊桥 enrollment 工具生成的 version 1 客户端 profile 路径。
文件包含设备私钥，Unix 上权限必须排除组和其他用户，例如 `chmod 600`。
必须是不超过 1 MiB 的普通文件，且仅包含一个 profile JSON 对象。

网关地址、Ed25519 provider 根指纹、网关 URI 身份及设备证书/私钥均从 profile
读取。两种承载都强制 TLS 1.3、双向认证与 `queqiao/1` ALPN，没有 insecure 或
WebPKI 覆盖选项。DNS 名称仅用于路由；网关身份由 provider URI 验证。

profile 在出站创建时读取；不负责注册或自动续期。使用官方工具续期后，需要重载/重启
该出站以读取新证书。

### transport

可靠承载类型：`tcp`（默认，TLS over TCP）或 `quic`（QUIC 双向 stream）。
`quic` 要求使用 `with_quic` 构建；不包含该 tag 的构建会明确拒绝配置，不会自动
改用 TCP。当前没有自动承载回落。

QUIC **仅使用可靠 stream**，明确禁用 DATAGRAM 和 0-RTT。协商 DATAGRAM 会允许
网关发送当前尚未实现的 coded TCP DATA，因此不能提前开启。每条 TCP flow 或 UDP
association 独占 QUIC 连接及 socket，暂不提供共享连接池或复用。

### network

允许的应用网络：`tcp` 和/或 `udp`，默认两者均启用。需要保留第一期 TCP-only
应用范围时，设置 `"network": "tcp"`。应用网络与外层 `transport` 相互独立。

### 拨号字段

支持[拨号字段](../shared/dial.md)，两种承载均通过 sing-box 公共拨号器，支持
detour、接口绑定、routing mark 与域名解析；QUIC 请求外层 UDP 连接。
profile 的 endpoint 为域名时，需按拨号字段要求配置域名解析器。
业务目标地址交给网关解析并应用网关策略。

## 当前功能

TCP 支持 OPEN 确认、RESET、逻辑字节偏移、有界乱序/重叠处理、ACK/ACK_RANGES 解析、
FIN/ACK_FINAL、双向半关闭、读写 deadline、打开阶段取消与关闭清理。

UDP 使用基本 `WOUD` version-1 association。每个 PACKET 保留一个 UDP 报文边界、
独立目标地址和包序号，报文上限为 65,507 字节。支持 IPv4、IPv6 和域名目标；回复必须
携带数值来源地址。64 包 bitmap 接受窗口内乱序，丢弃重复和过旧包。
小读取缓冲区只截断当前报文，剩余内容不会串入下一次读取。关闭时尝试 FIN/ACK_FINAL。

两种承载的 UDP PACKET 都走可靠 stream，因此相比 QUIC DATAGRAM 存在队头阻塞。
网关 UDP socket 与本地有界队列仍可能丢包，不能视作端到端可靠消息服务。

## 边界与生命周期

- 每出站最多 256 条正在打开或活动的 TCP flow / UDP association，超过即拒绝
- TCP 逻辑接收预算 4 MiB、最多 1024 个稀疏片段，上行未累计确认窗口 1 MiB
- UDP 最多保留 64 个待收包 / 4 MiB，队列溢出丢包，避免慢读者阻塞控制帧
- wire payload 固定上限 128 KiB，不可配置
- 拨号、TLS/QUIC、OPEN 共用 15 秒上限，或调用方更短的 deadline
- 控制写入上限 15 秒；TCP Close 最多花 100 ms 尝试 ABORT，UDP Close 最多
  等待 500 ms 的最终 ACK，然后取消承载
- QUIC 关闭额外用最多 2 秒等待已排入 stream 的字节被传输层确认，避免立刻关闭
  连接丢失最后一帧协议 ACK。内存追踪不保存 payload 或日志；未确认 packet-span
  记录和已确认区间各有 4096 条上限

承载丢失或网络接口切换会关闭当前 flow/association，不会偷偷重连或重放。
基本 UDP association 不提供恢复保留。TCP ABORT 失败时，网关可能保留自身恢复
元数据到其超时。

仍未实现 FEC/coded DATAGRAM、JOIN/resume、自动回落、连接池、多 lane、注册或
自动续期。不能视作完整协议支持，也不代表复现了官方 WAN 性能优化。
