# 鹊桥（Queqiao）

实验性原生 Queqiao protocol 1 出站，支持 TCP 与 UDP 代理。

```json
{
  "type": "queqiao",
  "tag": "queqiao-out",
  "profile_path": "/etc/sing-box/queqiao-profile.json",
  "transport": "tcp",
  "quic_initial_fallback": false,
  "quic_path_probe": false,
  "quic_data_isolation": false,
  "tcp_recovery": false,
  "tcp_lanes": 1,
  "udp_resume": false,
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
改用 TCP。仅显式开启下述选项时，首次建连可以有限回落到 TLS/TCP。

QUIC **仅使用可靠 stream**，明确禁用 DATAGRAM 和 0-RTT。协商 DATAGRAM 会允许
网关发送当前尚未实现的 coded TCP DATA，因此不能提前开启。每个出站独立维护最多
4 个认证后的 QUIC 连接，每连接最多 64 条正在等待、活动或排空的 stream，TCP flow
和 UDP association 可共享连接。不跨出站或 profile 共享。取消、关闭单流不会关闭其他流。
连接空闲 30 秒后回收；网络接口变化时丢弃整个旧池。共享握手保留首次拨号的上下文值，
但取消一个等待者不会中断其他等待者的握手。

### quic_initial_fallback

可选，**默认 false**，只能与 `"transport": "quic"` 配合使用，仍要求 `with_quic`
构建。该选项只影响尚未发送 OPEN 的首次建连，不迁移已经建立的 TCP flow 或 UDP association。

开启后，首次 QUIC 尝试最多等待 5 秒。只有连接超时、拒绝、重置或不可达等允许的网络
错误，才尝试一次同 profile、同网关 endpoint 的 TLS/TCP。身份/证书/协议拒绝、池容量
不足、stream 分配错误（包括等待配额超时）、权限错误和取消不会触发回落。QUIC 已成功提供 stream 后，OPEN 写入失败、响应
丢失或网关拒绝也不会回落，以免重复创建目标连接。不能识别的错误保留为失败。

QUIC、TCP、TLS 认证和 OPEN 共用原有 15 秒总预算，调用方更短的 deadline 优先。
没有并行竞速、永久偏好或共享 TCP 冷却状态；后续新 flow 仍先尝试 QUIC。
回落继续使用原 profile 的 TLS 1.3、双向认证、根指纹、网关 URI 和 ALPN 验证。
如同时开启 `tcp_recovery` 或 `udp_resume`，该 flow 后续恢复沿用首次实际选择的承载。

此新增选项已通过离线选择、错误分类、预算和清理测试，以及 `net.Pipe` 内存承载上的
TLS 1.3 双向认证、单次 OPEN 和数据回显验证。本机回环测试还覆盖实际 QUIC 握手超时后
在同端点进行 TCP 双向认证、socket 中断后自动 TCP JOIN／重放与 UDP resume，以及
QUIC 证书／ALPN 拒绝时禁止回落。这些使用协议测试 peer。另有显式启用的官方网关
本机测试，覆盖 5 个调用共享待完成 QUIC 握手、取消其中一个后其他调用认证回落、TCP
自动 JOIN 且不重建目标连接，以及 UDP resume 后真实目标观察到的源端点保持。
但严格单次探针稳定暴露恢复后首个回复丢失：真实目标已收到并发回该报文，之后的探针成功。
该交接问题仍未解决，因此官方网关 UDP 回落／恢复验收尚未全部通过，也不承诺 UDP
无丢失或 exactly-once。完整服务、更广泛的恢复压力和 WAN 验收仍未完成。

### quic_path_probe

可选，**默认关闭**，要求 `transport: "quic"` 和 `with_quic` 构建。每个新认证的池连接在
接纳应用流之前，使用专属可靠 stream 发送 4 个 1200 字节的 protocol-1 PROBE，随后
half-close 请求。并发调用共享该次预检。探测最多 3 秒，仍受原有建连／调用方预算限制，
逐一验证收到的回显头和 payload，包括超时前已经收到的错误前缀。

这是可选的回显协议一致性诊断，不是基本 TCP/UDP 合规要求、测速或方向性容量／丢包
测量。代码执行协议的每 stream 最多 128 帧、每帧最多 1200 字节、总 payload 最多
131072 字节限制；正常预检只发送 4800 字节，不协商 DATAGRAM、不更改拥塞控制。

debug 日志区分 conformant、incomplete、取消和传输失败。尚未收齐回显而读预算耗尽时关闭探测
stream；仍存活的连接可以继续入池，不据此判断对端不合规。已知错回显或提前 stream
EOF 则单独记录协议违规，并关闭该连接、禁止复用。取消单个调用不会影响其他等待者；
最后一个等待者取消或接口更新会退役旧连接及探测。收齐正确回显后，在同一预算内观察到的
额外尾部字节仍会被拒绝；仅响应 EOF 延迟不改变已完成回显的 conformant 状态。

探测阶段的超时／错误不会触发初始 TCP 回落。若同时开启 `quic_initial_fallback`，QUIC
认证之前的建连失败仍按原规则处理；认证后进入 PROBE 时，更短的调用方或 5 秒初始
尝试预算可以让该调用失败，但不会切换承载。后续新连接会独立预检，没有定期后台探测
或持久对端封禁。

### quic_data_isolation

可选，**默认关闭**，要求明确 `"transport": "quic"`、`with_quic` 构建和
`"tcp_recovery": true`。仅影响逻辑 TCP flow；UDP association 仍使用原有可靠池 stream。

首次 QUIC OPEN 设置 RESERVE_CONTROL，把池内 stream 保留为控制角色；再用一条
独立认证的 QUIC connection JOIN 相同 flow，作为唯一指定的上行 DATA 连接。
DATA 写忙时等待该 lane，不轮流向第二条连接发送 DATA。ACK、FIN 等控制帧优先走
控制 lane。接收端仍接受两条已准入 lane 上合法的 DATA／控制帧；官方网关根据 bulk
分类和共享池竞争决定下行路由，因此不保证双向每字节隔离，也不承诺吞吐提升。
短流的下行可能一直走控制连接。

初始 OPEN 保留 15 秒限制，隔离 JOIN 再增加最多 5 秒，两步均受调用方更短 deadline
约束。明确的临时网络错误或容量不足允许保留已有效建立的单控制 lane；身份、协议、
PROBE 或 stream 准入拒绝仍为错误。不会自动重试补满数据 lane。开启 quic_path_probe
时，每个新共享／专用连接均执行原有认证后预检。

共享、专用、正在建连、排空和退役中的 QUIC connection，共用每出站最多 4 条的硬预算。
专用 entry 不供其他 flow 复用，其 stream 关闭／排空后释放；共享 entry 仍保持每连接
最多 64 条 stream 和 30 秒空闲回收。隔离会占用原本可供共享流使用的连接容量，因此
可能更早触发新建流准入上限。取消连接须等 socket owner 完成清理才归还配额；恢复
退避期间不预占新连接配额。

数据 lane 故障后先退役，再把 DATA／重放切回控制 lane，不后台补满数据连接。
控制 lane 故障时，数据 lane 临时承担控制，并用相同 principal 的 JOIN|RESERVE_CONTROL
恢复控制角色；全部故障则先恢复控制。角色替代共用原有最多 3 次 JOIN／40 秒预算；
临时错误耗尽后可以保留存活的单数据 lane，但不能掩盖授权／协议拒绝。迟到 JOIN 不得
复活已关闭 flow；JOIN 的传输 EOF 属于准入失败，不能变成应用正常 FIN。
正常结束对两条可能承载最终帧的 stream 做原有有界排空后再释放资源，取消则及时中断。

quic_initial_fallback 仍只作用于 OPEN 之前。若首次选择了认证 TLS/TCP，此 flow
沿用普通单 TLS lane，不保留 QUIC 角色。OPEN 后的隔离 JOIN 失败不会切换 TCP。
DATAGRAM 和 0-RTT 保持关闭。

### tcp_lanes

可选，**默认 1**；省略或 `0` 也表示 1。目前仅额外支持 `2`，要求明确配置
`"transport": "tcp"` 和 `"tcp_recovery": true`。只影响 TCP logical flow；UDP
association 仍使用单条承载。不能混用 QUIC/TCP，也不启用 QUIC 的控制 lane 保留角色。

配置为 `2` 时，先认证 OPEN lane，再用相同 profile、principal、session/flow 认证
JOIN lane，两条均收到 OPEN_OK 后才向调用方返回连接。初始 OPEN 保留 15 秒预算，
随后第二条准入最多 5 秒（合计最多 20 秒）；两步都受调用方更短 deadline 限制。拒绝则建连失败，不静默返回不完整 bundle，也不另行 OPEN
第二个目标连接。

应用数据块在可用 lane 间轮流发送；某条 DATA 写阻塞时，ACK／控制帧可以使用另一条
空闲 lane。这是可选的可靠承载调度，不是测速、自适应调度器或吞吐提升保证。两条 lane
共同使用同一份有界接收／重放状态，重复片段仅交付一次；尚保留在接收缓冲中的重叠字节
必须一致，已经被应用读取的历史字节不额外保留比较。

单条故障后退役该 lane，将未确认字节及 FIN 状态重放到存活 lane。允许降为一条，
不在后台自动补满；全部断开时，使用现有有界 TCP recovery 预算 JOIN 替代 lane。
每个 flow 最多占两条活动／待准入 lane 位置。关闭 flow 或接口变化会关闭所有对应承载；
没有必要逻辑结束状态的提前 EOF 仍视为错误。

### tcp_recovery

可选，**默认 false**。开启后，已经建立的 TCP flow 可在可靠 lane 故障时，通过相同
承载、profile、session/flow 的 JOIN 恢复。不会偷偷 OPEN 新的目标连接，也不做承载
回落。UDP association 使用独立的 `udp_resume` 开关。

上行最多保留 1 MiB / 1024 个片段的未确认 payload；仅累计 ACK 释放 replay 缓冲，
selective ACK 范围仍严格校验。下行按逻辑偏移去重，不把重放字节重复交给应用。
开启恢复时，CloseWrite 会等之前所有字节得到累计 ACK 才发送 FIN，避免在网关已经
半关闭目标后再重放 DATA。

每条逻辑 TCP flow 的**整个生命周期最多 3 次 JOIN 尝试**；每次断链恢复**最多 40 秒**，
每次认证及 JOIN 最多 5 秒，并有退避。最后一次因容量拒绝的重试等待 15 秒，以适应
官方网关对年轻 lane 的保护窗口；普通重试退避 100/200 ms。明确身份验证失败、协议错误
及永久 JOIN 拒绝立即终止恢复；无法区分原因的握手/I/O 失败仍受上述次数和时间上限约束。

故障期间读写 deadline 继续生效，也可清除。Write 超时时，返回的已接受字节数可能
包括已经进入 replay 缓冲的字节；调用方只能重试返回计数之后的部分。Close 和出站
关闭会取消恢复。网络接口更新仍主动终止旧 flow，不会悄悄跨路由变化恢复。

等待开始实际写入时超时，不会接受新字节，也不会标记 FIN；清除或延长 deadline 后，
可重试未接受的字节或 CloseWrite。一旦开始实际写入，I/O 错误可能意味着交付状态不确定，
此时已接受的 replay 字节和 FIN 由恢复流程处理。

### udp_resume

可选，**默认 false**。开启后采用 `WOUD` version 2 association 和一次性恢复 token。
可靠承载断开后，使用同一 profile、设备身份、transport 和出站 QUIC 池重新 OPEN，
请求取回原网关 UDP relay socket。每次成功恢复都使用新的 session/flow ID、token 和
报文序号窗口，不额外占用一个逻辑连接名额。

取回原 socket 可保持远端目的地看到的源地址和端口，包括同 association 的多个目标。
如果网关只返回 fresh relay，当前 PacketConn 会明确失败，不会悄悄更换源端点。
token 未知、过期、已使用或身份不同，都可能导致无法取回原 relay。OPEN_OK 丢失还可能
使 token 已被消费但新 token 未收到，因此恢复是尽力而为。官方网关仅在承载故障时
有界保留 relay，取回有效期为 30 秒，并设容量上限及周期清理；正常关闭不会保留。

**不会重放任何发出的 UDP 报文。** WriteTo 遇到承载错误后等待恢复，成功取回原 relay
后将这一个交付不明的报文视为已消耗，返回其长度和 nil；该报文可能已经送达，也可能丢失。
这样 sing-box 的报文转发循环可以继续，不会重放可能已送达的报文。恢复失败、deadline
或 Close 中止等待时，WriteTo 返回 0 和错误，但报文仍可能已送达，应用自行重试可能重复。
WriteTo 成功不是端到端送达确认。断链在途和 relay 交接期间都可能丢包。64 个序号的接收窗口只在
同一 association 内去重，恢复后重置，不能按报文内容实现跨恢复去重。此前已接收并
排队的报文仍可读取。不存在应用层可靠传递或 exactly-once 保证。

一个 PacketConn 整个生命周期最多 **3 次恢复尝试**；每次认证 OPEN 最多 5 秒，
每次故障的总预算为 **20 秒**。第 1/2/3 次尝试前分别等待 100/200/400 ms。
协议错误、明确的身份校验失败和永久拒绝会终止恢复。读写 deadline 在恢复期间仍有效；
WriteTo 等待新承载，出站至多额外持有一个编码报文副本。Close、出站关闭或网络接口更新
会取消恢复。失败或被取消的关闭可能留下网关侧有界保留项，直至其过期。
token 仅保留在内存，不写日志或持久化。

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

UDP 默认使用基本 `WOUD` version-1 association，开启 `udp_resume` 后使用 version 2。每个 PACKET 保留一个 UDP 报文边界、
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
- QUIC 单流关闭额外用最多 2 秒等待已排入 stream 的字节被传输层确认；按实际
  stream ID 分别追踪，即使一个包包含多条 stream。追踪不保存 payload 或日志；
  每连接最多 4096 个待确认包记录、65536 条 packet-span 与 65536 条已确认区间。
  超出预算会让该次排空失败，不会无限保留历史
- QUIC 连接接收窗口上限为 16 MiB，各流原有应用层内存限制继续生效。池连接到
  设备/网关完整证书链中最早的到期时间即关闭，包含 issuer 与根证书

关闭 `tcp_recovery` 时，承载丢失会结束 TCP flow；开启后仅进行上述有界 JOIN/replay。
基本 UDP association 在承载丢失时失败，开启 `udp_resume` 后按上述有界规则取回 relay。网络接口切换会关闭现有活动。TCP ABORT 失败时，网关可能保留自身恢复
元数据到其超时。

此版本包含经过离线向量、预算和模糊测试验证的 FEC 编解码与分片重组模块，但未接入
网络收发路径。出站不协商 DATAGRAM，离线模块不代表在线 FEC/coded DATAGRAM 支持。
活跃 flow 的跨承载回落、多 lane、注册和自动续期仍未实现。不能视作完整协议支持，也不代表复现了
官方 WAN 性能优化。

## 验证状态与已知限制

截至 2026-09-30，独立审查修复版本通过了 Queqiao 包的默认及 `with_quic` race
测试、使用临时本地身份的官方网关回环互通，以及两种构建配置的 CLI 构建。
这些结果不代表整个 sing-box 项目全部测试通过，也不构成生产或 WAN 性能保证。

此前一次 TCP 大数据全双工与半关闭互通测试出现 `unexpected EOF`，仍未解决。
受控测试另行复现了官方网关在 FIN 物理发送之前提前关闭 lane 的竞态机制，但尚未
证明它就是该次历史 EOF 的原因。后续成功测试没有消除这一未决风险；不应通过启用
恢复选项将其视作已修复。

当前测试环境的 netlink/netns 权限限制阻挡了完整 SOCKS 服务验证，TUN 与实际系统
路由也尚未验收。全项目检查另有外网 `tlsfragment` 测试和 Go 1.25.13 下实验性
`libbox`/`boxdd` 链接限制，不能由上述包级通过结果替代。
