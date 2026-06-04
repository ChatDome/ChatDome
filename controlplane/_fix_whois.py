"""One-shot patch: replace HTTP ip-api.com with HTTPS ipwho.is in tools.py."""
import pathlib

target = pathlib.Path(__file__).parent / "src" / "chatdome" / "agent" / "tools.py"
content = target.read_text(encoding="utf-8")

OLD = '''    async def _handle_whois_lookup(self, args: dict[str, Any]) -> str:
        """Look up IP geolocation via ip-api.com."""
        ip = args.get("ip", "")
        if not ip:
            return "缺少 IP 地址参数"

        try:
            client = await self._get_http_client()
            response = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"lang": "zh-CN", "fields": "status,message,country,regionName,city,isp,org,as,query"},
            )
            data = response.json()

            if data.get("status") == "fail":
                return f"IP 查询失败: {data.get('message', '未知错误')}"

            lines = [
                f"IP: {data.get('query', ip)}",
                f"国家: {data.get('country', '未知')}",
                f"地区: {data.get('regionName', '未知')}",
                f"城市: {data.get('city', '未知')}",
                f"ISP: {data.get('isp', '未知')}",
                f"组织: {data.get('org', '未知')}",
                f"AS: {data.get('as', '未知')}",
            ]
            return "\\n".join(lines)

        except httpx.TimeoutException:
            return f"IP 查询超时: {ip}"
        except Exception as e:
            logger.error("Whois lookup failed for %s: %s", ip, e)
            return f"IP 查询异常: {e}"'''

NEW = '''    async def _handle_whois_lookup(self, args: dict[str, Any]) -> str:
        """Look up IP geolocation via ipwho.is (HTTPS)."""
        ip = args.get("ip", "")
        if not ip:
            return "缺少 IP 地址参数"

        try:
            client = await self._get_http_client()
            response = await client.get(f"https://ipwho.is/{ip}")
            data = response.json()

            if not data.get("success", False):
                return f"IP 查询失败: {data.get('message', '未知错误')}"

            connection = data.get("connection", {})
            asn = connection.get("asn", "")
            org = connection.get("org", "未知")
            as_display = f"AS{asn} {org}" if asn else org

            lines = [
                f"IP: {data.get('ip', ip)}",
                f"国家: {data.get('country', '未知')}",
                f"地区: {data.get('region', '未知')}",
                f"城市: {data.get('city', '未知')}",
                f"ISP: {connection.get('isp', '未知')}",
                f"组织: {org}",
                f"AS: {as_display}",
            ]
            return "\\n".join(lines)

        except httpx.TimeoutException:
            return f"IP 查询超时: {ip}"
        except Exception as e:
            logger.error("Whois lookup failed for %s: %s", ip, e)
            return f"IP 查询异常: {e}"'''

# Normalize line endings for matching
content_norm = content.replace('\r\n', '\n')
old_norm = OLD.replace('\r\n', '\n')
new_norm = NEW.replace('\r\n', '\n')

if old_norm not in content_norm:
    print("ERROR: Old pattern not found in file!")
    raise SystemExit(1)

count = content_norm.count(old_norm)
if count != 1:
    print(f"ERROR: Pattern found {count} times, expected 1")
    raise SystemExit(1)

patched = content_norm.replace(old_norm, new_norm)

# Preserve original line ending style
if '\r\n' in content:
    patched = patched.replace('\n', '\r\n')

target.write_text(patched, encoding="utf-8")
print(f"SUCCESS: Patched tools.py ({count} replacement)")
print(f"  - Removed: http://ip-api.com/json/")
print(f"  - Added:   https://ipwho.is/")
