import os
import sys
import json
import urllib.parse
import base64

def parse_proxy_url(url_str: str) -> dict:
    url_str = url_str.strip()
    parsed = urllib.parse.urlparse(url_str)
    scheme = parsed.scheme.lower()
    params = urllib.parse.parse_qs(parsed.query)

    outbound = {}

    # 1. Hysteria 2
    if scheme in ("hy2", "hysteria2"):
        outbound = {
            "type": "hysteria2",
            "tag": "proxy-out",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": parsed.username or parsed.netloc.split("@")[0],
            "tls": {
                "enabled": True,
                "server_name": params.get("sni", [parsed.hostname])[0],
                "insecure": params.get("insecure", ["0"])[0] in ("1", "true")
            }
        }

    # 2. VLESS (支持 Reality, WS, TLS)
    elif scheme == "vless":
        security = params.get("security", ["none"])[0].lower()
        tls_config = {"enabled": False}
        
        if security == "reality":
            tls_config = {
                "enabled": True,
                "server_name": params.get("sni", [parsed.hostname])[0],
                "reality": {
                    "enabled": True,
                    "public_key": params.get("pbk", [""])[0],
                    "short_id": params.get("sid", [""])[0]
                }
            }
        elif security == "tls":
            tls_config = {
                "enabled": True,
                "server_name": params.get("sni", [parsed.hostname])[0],
                "insecure": params.get("insecure", ["0"])[0] in ("1", "true")
            }

        transport_type = params.get("type", ["tcp"])[0].lower()
        transport = {}
        if transport_type == "ws":
            transport = {
                "type": "ws",
                "path": params.get("path", ["/"])[0]
            }

        outbound = {
            "type": "vless",
            "tag": "proxy-out",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "uuid": parsed.username,
            "tls": tls_config
        }
        if transport:
            outbound["transport"] = transport

    # 3. Trojan
    elif scheme == "trojan":
        outbound = {
            "type": "trojan",
            "tag": "proxy-out",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": parsed.username or parsed.netloc.split("@")[0],
            "tls": {
                "enabled": True,
                "server_name": params.get("sni", [parsed.hostname])[0],
                "insecure": params.get("insecure", ["0"])[0] in ("1", "true")
            }
        }

    # 4. Shadowsocks
    elif scheme == "ss":
        user_info = parsed.username or parsed.netloc.split("@")[0]
        # 处理 base64 编码的 user_info
        if ":" not in user_info:
            try:
                # 补全 padding
                user_info += "=" * (-len(user_info) % 4)
                user_info = base64.b64decode(user_info).decode()
            except Exception:
                pass
        
        method, password = user_info.split(":", 1)
        outbound = {
            "type": "shadowsocks",
            "tag": "proxy-out",
            "server": parsed.hostname,
            "server_port": parsed.port or 8388,
            "method": method,
            "password": password
        }

    else:
        raise ValueError(f"暂不支持的协议类型: {scheme}")

    return outbound

def main():
    proxy_url = os.environ.get("PROXY_URL", "").strip()
    raw_config = os.environ.get("SING_BOX_CONFIG", "").strip()

    # 如果用户直接提供了完整 JSON 配置，优先使用
    if raw_config:
        try:
            config = json.loads(raw_config)
            with open("sing-box-config.json", "w") as f:
                json.dump(config, f, indent=2)
            print("✅ 已成功载入 SING_BOX_CONFIG 完整配置")
            return
        except Exception as e:
            print(f"⚠️ 解析 SING_BOX_CONFIG 失败: {e}，尝试回退解析 PROXY_URL")

    if not proxy_url:
        print("❌ 未提供 PROXY_URL 或 SING_BOX_CONFIG")
        sys.exit(1)

    try:
        outbound = parse_proxy_url(proxy_url)
        full_config = {
            "log": {
                "level": "info",
                "timestamp": True
            },
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": 10808
                }
            ],
            "outbounds": [
                outbound,
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ]
        }

        with open("sing-box-config.json", "w", encoding="utf-8") as f:
            json.dump(full_config, f, indent=2)
        print(f"✅ 成功生成 sing-box 配置文件 (协议: {outbound.get('type')})")
    except Exception as e:
        print(f"❌ 生成代理配置失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
