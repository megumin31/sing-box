# 本机 sing-box 客户端 → 原生 sing-box 服务端

这是可靠 TLS/TCP 与 QUIC stream 预览。服务端不需要 companion 进程。
QUIC 客户端和 `transport: auto` 服务端使用带 `with_quic` 的二进制；
TCP-only 资产的服务端必须将 `transport` 改为 `tcp`。

## 准备已有合法身份

本发布不签发证书，也不提供 enrollment/renewal。先从受信任的身份签发流程
取得版本 1 客户端 profile 和服务端 gateway credentials；或按 template 字段
填写已有身份。所有尖括号值都必须替换，模板本身不能运行。
服务端账户/设备 IDs 和 public_key 必须匹配客户端证书及 Ed25519 公钥。
两端 provider_id、gateway_id、root_pin 和 root certificate 必须一致。
IDs 为 32 位小写十六进制；root_pin 为根证书 SHA256 的无填充 URL-safe base64；
provider_id 是根公钥 SPKI SHA256 的前 16 字节十六进制。
叶证书及链必须通过各自 serverAuth/clientAuth 校验，链包含 provider root。
证书 URI 分别为 `queqiao://<provider_id>/gateway/<gateway_id>` 和
`queqiao://<provider_id>/account/<account_id>/device/<device_id>`。
这是协议身份校验，普通 WebPKI 证书或随意生成的自签叶证书不能替代它。

profile endpoint 填服务端可达 IP 和选定端口，例如 `<SERVER_IP>:8443`，
IPv6 使用 `[<SERVER_IPV6>]:8443`。使用域名 endpoint 时还需配置 sing-box
普通 domain_resolver；这里以 IP 避免额外 DNS 配置。确认端口可用并可达，
不要直接覆盖已有服务配置。例子不更改系统代理、TUN、路由或防火墙。

## Linux 服务端

在一个独立目录放置解压得到的 sing-box、server.json 与真实
gateway-credentials.json，替换 server.json 的 users 字段后执行：

```sh
chmod 600 gateway-credentials.json
./sing-box check -c server.json
./sing-box run -c server.json
```

配置监听 TCP 和 UDP 8443；可改为其它非冲突端口，两端 endpoint 同步修改。
这是前台启动命令，不安装服务。凭据必须是普通、非符号链接文件且不超过1MiB。

## Mac 或 Linux 本机客户端

在独立目录放置适合平台的 sing-box、真实 client-profile.json 和客户端配置：

```sh
chmod 600 client-profile.json
./sing-box check -c client-quic.json
./sing-box run -c client-quic.json
```

本地 SOCKS 地址是 `127.0.0.1:1080`。另一个终端可手动验证：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

如需 DATA/control 隔离，选 client-quic-isolated.json；如需 TLS/TCP，选
client-tcp.json。客户端配置的恢复与 active fallback 是显式启用的选项，
默认配置并不启用它们。配置文件使用相对身份路径，应从该目录运行。
示例不含真实身份；不要把填好的身份文件提交或发布。

## 预览覆盖

Linux amd64 双端的两个低负载900秒故障窗口通过，含精确字节/EOF、UDP
单发及端口保持、取消和资源回收。首次22.729秒启动超时未解释，后续未复现。
当前源码race为504/446 PASS，8/3 opt-in SKIP。线上FEC未完成，非对称TCP
黑洞、高负载、TUN与长期生产稳定性未验证。Mac资产仅做构建/version检查。
20s idle setting来自本次有限测试；不承诺21秒完整应用恢复。
完整限制和证据见根目录 queqiao-active-migration-audit.md。
