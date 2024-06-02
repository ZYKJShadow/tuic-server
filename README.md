## tuic-server

使用go实现的tuic代理服务器，具体协议请查看[tuic-protocol-go](https://github.com/ZYKJShadow/tuic-protocol-go)，QUIC核心使用[quic-go](https://github.com/quic-go/quic-go)库实现，该库还有许多未知bug，仅供学习。

客户端请参阅[tuic-client](https://github.com/ZYKJShadow/tuic-client)

服务器配置示例：
```json
{
  "server": "127.0.0.1:8888",
  "cert_path": "cert/cert.pem",
  "private_key": "cert/key.pem",
  "password": "0dcd8b80-603c-49dd-bfb7-61ebcfd5fbb8",
  "alpn": [
    "h3"
  ],
  "zero_rtt_handshake": true,
  "auth_timeout": 3,
  "max_idle_time": 3,
  "max_packet_size": 2048
}
```
字段说明：
1. server: 监听地址
2. cert_path: 证书路径
3. private_key: 私钥路径
4. zero_rtt_handshake: 是否启用0rtt
5. alpn:协议列表
6. auth_timeout: 客户端认证超时时间
7. max_idle_time: 各种网络传输超时时间
8. max_packet_size: 分片包大小