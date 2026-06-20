import base64
import json
import os
import hmac
import time
import uuid
import httpx
import random
import qrcode
import hashlib
import warnings
import socket

from functools import reduce
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from typing import Optional, Tuple
from loguru import logger

class BilibiliClient:

    SHOW_REQUEST_HOST = "show.bilibili.com"
    SHOW_REQUEST_PROBE_PATH = "/api/ticket/order/createV2"
    SHOW_REQUEST_IP_PROBE_TIMEOUT = 2.0
    SHOW_REQUEST_IP_PROBE_CACHE_TTL = 300
    SHOW_REQUEST_IP_USABLE_STATUS_CODES = {200, 400, 401, 403, 405, 412, 429}
    # 默认池来自 show.bilibili.com 多 DNS 源 A 记录，并已用直连 GET createV2 验证返回 405。
    SHOW_REQUEST_VALIDATED_IPS = (
        "183.131.147.29",
        "183.131.147.28",
        "183.131.147.30",
        "114.230.222.142",
        "114.230.222.173",
        "183.131.147.27",
        "114.230.222.141",
        "114.230.222.140",
        "114.230.222.138",
        "61.147.236.103",
        "61.147.236.102",
        "183.131.147.48",
        "61.147.236.101",
        "114.230.222.139",
        "114.230.222.172",
        "117.21.179.20",
        "61.147.236.104",
        "117.21.179.19",
        "117.21.179.18",
        "175.4.62.127",
        "175.4.62.128",
        "175.4.62.129",
        "116.207.163.63",
        "116.207.163.64",
        "116.207.163.65",
        "116.207.163.66",
        "164.52.1.59",
        "164.52.1.60",
        "164.52.1.61",
        "164.52.1.62",
    )
    SHOW_REQUEST_CANDIDATE_IPS = SHOW_REQUEST_VALIDATED_IPS

    def __init__(self):
        self.uid = 0
        model_list = {
            "OnePlus": ["PKR110","PJD110","PJZ110","PKU110","PJA110","PJF110","PJX110"], 
            "IQOO": ["V2329A", "V2408A", "V2307A", "V2304A", "V2254A"],
            "HONOR": ["DVD-AN00", "PTP-AN20", "ROD2-W69", "ROD2-W09", "ROL-W00"],
            "Vivo": ["V2324A", "V2229A", "V2241A", "V2359A", "V2454A", "V2364A", "V2429A", "V2343A", "V2435A"],
            "Realme": ["RMX5060", "RMX3946", "RMX3948", "RMX5010"],
            "OPPO": ["PFFM20", "PJJ110", "PJW110", "PKM110", "PHU110"],
            # "HUAWEI": ["PLU-AL00", "PLA-AL10", "CLS-AL00", "ALN-AL10", "BRA-AL00", "CET-AL00", "VDE-AL00", "ADY-AL00"]
        }
        self.brand = random.choice(list(model_list.keys()))
        self.model = random.choice(model_list[self.brand])
        self.show_init = False
        self.wbi = False
        self.app_sign = False
        self.rate_limit_events = []
        self.last_cdn_info = {"provider": "unknown", "zone": "unknown", "raw": ""}
        self._request_ip_pool = []
        self._current_request_ip = None
        self._request_ip_probe_cache = {}
        self._get_newest_version()
        self.ua = self._gen_ua()
        self.headers = {
            'User-Agent': self.ua,
        }
        self.screen_info = "362*795*24"
        self.canvasFp = "".join([str(random.choice("0123456789abcdef")) for _ in range(32)])
        self.webglFp = "".join([str(random.choice("0123456789abcdef")) for _ in range(32)])
        self.feSign = "".join([str(random.choice("0123456789abcdef")) for _ in range(32)])
        self.session = httpx.Client(
            headers=self.headers,
            timeout=10,
            http2=True,
            event_hooks={
                "request": [self._on_request],
                "response": [self._on_response]
            },
            verify=False
        )
        self._init_buvid()
        self._getKeys()
        self.risk_header = self._gen_risk_header()

    def _get_newest_version(self):
        # resp = self.get("https://app.bilibili.com/x/v2/version?mobi_app=android")
        # use origin httpx
        tmp_headers = {
            'User-Agent': "Mozilla/5.0",
        }
        try:
            resp = httpx.get("https://app.bilibili.com/x/v2/version?mobi_app=android", headers=tmp_headers).json()
        except Exception as e:
            logger.error(f"获取最新版本失败: {e} Fallback to 8.35.0")
            self.biliAppVersion = "8350200"
            self.biliAppVersionName = "8.35.0"
            return
        self.biliAppVersion = resp['data'][0]['build']
        self.biliAppVersionName = resp['data'][0]['version']

    def _gen_ua(self):
        _dist = [
            f"Mozilla/5.0 (Linux; Android 15; {self.model} Build/{self._gen_build_id()}; wv)",
            f"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0",
            f"Chrome/135.0.7049.{random.randint(1,150)} Mobile Safari/537.36",
            f"BiliApp/{self.biliAppVersion}",
            f"mobi_app/android",
            f"isNotchWindow/1",
            f"NotchHeight={random.randint(20, 40)}",
            f"mallVersion/{self.biliAppVersion}",
            f"mVersion/296",
            f"disable_rcmd/0",
            f"magent/BILI_H5_ANDROID_15_{self.biliAppVersionName}_{self.biliAppVersion}",
        ]
        return " ".join(_dist)

    def _gen_build_id(self):
        return f"{random.choice('AB')}P{random.randint(1,4)}A.240{random.randint(1,9)}{random.randint(1,2)}{random.randint(1,9)}.0{random.randint(1,2)}{random.randint(1,9)}"


    def _hmac_sha256(self, key, message):
        return hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest().hex()

    def _getKeys(self):
        ts = int(time.time())
        o = self._hmac_sha256("XgwSnGZ1p",f"ts{ts}")
        csrf = self.session.cookies.get("bili_jct")
        if csrf is None:
            csrf = ""
        params = {
            "key_id":"ec02",
            "hexsign":o,
            "context[ts]":ts,
            "csrf": csrf,
        }
        resp = self.post("https://api.bilibili.com/bapis/bilibili.api.ticket.v1.Ticket/GenWebTicket", params=params)
        if resp['code'] != 0:
            img_key = ""
            sub_key = ""
            bili_ticket = ""
            bili_ticket_expires = 0
            logger.warning(f"获取ticket失败，无法访问Wbi接口: {resp}")
        else:
            img_url: str = resp['data']['nav']['img']
            sub_url: str = resp['data']['nav']['sub']
            bili_ticket: str = resp['data']['ticket']
            bili_ticket_expires: int = resp['data']['created_at'] + resp['data']['ttl']
            img_key = img_url.rsplit('/', 1)[1].split('.')[0]
            sub_key = sub_url.rsplit('/', 1)[1].split('.')[0]
        self.img_key = img_key
        self.sub_key = sub_key
        self.bili_ticket = bili_ticket
        self.session.cookies.update({
            "bili_ticket": bili_ticket,
            "bili_ticket_expires": str(bili_ticket_expires),
        })

    def get_csrf(self):
        csrf = None
        csrf = self.session.cookies.get("bili_jct", domain=".bilibili.com")
        if csrf is not None:
            return csrf
        csrf = self.session.cookies.get("bili_jct", domain="")
        if csrf is not None:
            return csrf
        return ""

    def _wbi_sign(self, params: dict) -> dict:
        mixinKeyEncTab = [
            46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35, 27, 43, 5, 49,
            33, 9, 42, 19, 29, 28, 14, 39, 12, 38, 41, 13, 37, 48, 7, 16, 24, 55, 40,
            61, 26, 17, 0, 1, 60, 51, 30, 4, 22, 25, 54, 21, 56, 59, 6, 63, 57, 62, 11,
            36, 20, 34, 44, 52
        ]
        def getMixinKey(orig: str):
            '对 imgKey 和 subKey 进行字符顺序打乱编码'
            return reduce(lambda s, i: s + orig[i], mixinKeyEncTab, '')[:32]
        mixin_key = getMixinKey(self.img_key + self.sub_key)
        curr_time = round(time.time())
        params['wts'] = curr_time                                   # 添加 wts 字段
        params = dict(sorted(params.items()))                       # 按照 key 重排参数
        params = {
            k : ''.join(filter(lambda chr: chr not in "!'()*", str(v)))
            for k, v 
            in params.items()
        }
        query = urlencode(params)                      # 序列化参数
        wbi_sign = hashlib.md5((query + mixin_key).encode()).hexdigest()    # 计算 w_rid
        params['w_rid'] = wbi_sign
        return curr_time, wbi_sign

    def _init_buvid(self):
        # self.get("https://www.bilibili.com")
        random_md5_1 = hashlib.md5(str(random.random()).encode()).hexdigest()
        random_md5_2 = hashlib.md5(str(random.random()).encode()).hexdigest()
        buvid = f"XU{random_md5_1[2]}{random_md5_1[12]}{random_md5_1[22]}{random_md5_1}"
        buvid = buvid.upper()
        self.buvid = buvid
        fp_raw = random_md5_2 + time.strftime("%Y%m%d%H%M%S", time.localtime()) + "".join([str(random.choice("0123456789abcdef")) for _ in range(16)])
        fp_raw_sub_str = [fp_raw[i:i+2] for i in range(0, len(fp_raw), 2)]
        veri_code = 0
        for i in range(0, len(fp_raw_sub_str), 2):
            veri_code += int(fp_raw_sub_str[i], 16)
        veri_code = hex(veri_code%256)[2:]
        self.fp = f"{fp_raw}{veri_code}"
        resp = self.get("https://api.bilibili.com/x/frontend/finger/spi")
        if resp["code"] != 0:
            self.session.cookies.update({
                "buvid3": "",
                "buvid4": "",
                "buvid_fp": self.fp,
                "_uuid": self.gen_uuid_infoc(),
            })
            return
        self.session.cookies.update({
            "buvid3": resp["data"]["b_3"],
            "buvid4": resp["data"]["b_4"],
            "buvid_fp": self.fp,
            "_uuid": self.gen_uuid_infoc(),
        })


    def gen_uuid_infoc(self) -> str:
        t = int(time.time() * 1000) % 100000
        return str(uuid.uuid4()) + str(t).ljust(5, "0") + "infoc"

    def init_show_cookies(self):
        self.devicefp = uuid.uuid4().hex
        self.session.cookies.update({
            "msource": "bilibiliapp",
            "kfcSource": "bilibiliapp",
            "deviceFingerprint": self.devicefp,
        })
        self.show_init = True

    def _on_request(self, request: httpx.Request):
        if self.wbi:
            wts, w_rid = self._wbi_sign(dict(request.url.params))
            p = request.url.params
            p = p.set("wts", wts)
            p = p.set("w_rid", w_rid)
            request.url = request.url.copy_with(params=p)
        if self.app_sign:
            # TODO: 实现app_sign
            pass
        self.session.cookies.update({
            "identify": quote(urlencode(self._app_sign({"ts": int(time.time() * 1000)}))),
            "screenInfo": self.screen_info,
            "canvasFp": self.canvasFp,
            "webglFp": self.webglFp,
            "feSign": self.feSign,
        })
        if not self.show_init and request.url.host == "show.bilibili.com":
            logger.warning("show ck not init")
        pass

    def _on_response(self, response: httpx.Response):
        cdn_info = self._extract_cdn_info(response.headers)
        if cdn_info["provider"] != "unknown":
            self.last_cdn_info = cdn_info

    def _safe_header_dict(self, headers) -> dict:
        sensitive_headers = {"set-cookie", "cookie", "authorization", "proxy-authorization"}
        result = {}
        for key, value in headers.items():
            result[key] = "<redacted>" if key.lower() in sensitive_headers else value
        return result

    def _redact_url(self, url: str) -> str:
        sensitive_params = {"token", "ptoken", "ctoken", "csrf", "csrf_token", "bili_jct", "sessdata", "qrcode_key", "key", "access_key", "voucher", "challenge", "validate", "seccode", "code"}
        try:
            parsed = urlparse(str(url))
            query = []
            for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                query.append((key, "<redacted>" if key.lower() in sensitive_params else value))
            return urlunparse(parsed._replace(query=urlencode(query)))
        except Exception:
            return str(url)

    def _extract_cdn_info(self, headers) -> dict:
        header_map = {key.lower(): value for key, value in headers.items()}
        webcdn = header_map.get("x-cache-webcdn", "")
        via = header_map.get("via", "")
        server = header_map.get("server", "")
        raw = webcdn or via or server
        if webcdn:
            marker = "blzone"
            zone = webcdn
            if marker in webcdn:
                tail = webcdn.split(marker, 1)[1]
                zone_suffix = []
                for char in tail:
                    if char.isalnum() or char in "-_":
                        zone_suffix.append(char)
                    else:
                        break
                if zone_suffix:
                    zone = marker + "".join(zone_suffix)
            return {"provider": "bilicdn", "zone": zone, "raw": webcdn}
        if via:
            return {"provider": "via", "zone": via, "raw": via}
        if server:
            return {"provider": "server", "zone": server, "raw": server}
        return {"provider": "unknown", "zone": "unknown", "raw": raw}

    def _rate_limit_summary(self) -> dict:
        now = time.time()
        window_seconds = 600
        self.rate_limit_events = [event for event in self.rate_limit_events if now - event["timestamp"] <= window_seconds][-200:]
        endpoint_counts = {}
        zone_counts = {}
        provider_counts = {}
        path_zone_counts = {}
        for event in self.rate_limit_events:
            endpoint_counts[event["endpoint"]] = endpoint_counts.get(event["endpoint"], 0) + 1
            zone_counts[event["zone"]] = zone_counts.get(event["zone"], 0) + 1
            provider_counts[event["provider"]] = provider_counts.get(event["provider"], 0) + 1
            if event["provider"] in {"bilicdn", "via"} and event["zone"] != "unknown":
                path_zone_counts[event["zone"]] = path_zone_counts.get(event["zone"], 0) + 1
        total = len(self.rate_limit_events)
        classification = "样本不足，暂不能判断限流范围"
        if total >= 3:
            top_endpoint, top_endpoint_count = max(endpoint_counts.items(), key=lambda item: item[1])
            if path_zone_counts:
                top_path_zone, top_path_zone_count = max(path_zone_counts.items(), key=lambda item: item[1])
                if top_path_zone_count / total >= 0.7:
                    classification = "疑似特定 CDN zone 或网络路径集中限流"
                elif top_endpoint_count / total >= 0.7 and len(path_zone_counts) > 1:
                    classification = "疑似接口级或全局限流"
                elif top_endpoint_count / total >= 0.7:
                    classification = "疑似单接口限流，CDN zone 样本不足"
                else:
                    classification = "多接口或多区域分散限流"
            elif top_endpoint_count / total >= 0.7:
                classification = "疑似单接口限流，CDN zone 信息不足"
            else:
                classification = "多接口分散限流，CDN zone 信息不足"
        return {"window_seconds": window_seconds, "recent_total": total, "endpoint_counts": endpoint_counts, "zone_counts": zone_counts, "path_zone_counts": path_zone_counts, "provider_counts": provider_counts, "classification": classification}

    def _split_request_ips(self, ip):
        if ip is None:
            return []
        if isinstance(ip, (list, tuple, set)):
            raw_items = ip
        else:
            raw_items = str(ip).replace(";", ",").replace("\n", ",").split(",")
        return [str(item).strip() for item in raw_items if str(item).strip()]

    def _unique_request_ips(self, ips):
        result = []
        for ip in ips:
            if ip and ip not in result:
                result.append(ip)
        return result

    def _extend_request_ip_pool(self, ips):
        if not hasattr(self, "_request_ip_pool"):
            self._request_ip_pool = []
        for ip in ips:
            if ip not in self._request_ip_pool:
                self._request_ip_pool.append(ip)

    def _resolve_request_ips(self, hostname: str):
        if not hostname:
            return []
        try:
            infos = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
        except Exception as e:
            logger.warning(f"解析请求 IP 失败: host={hostname} error={e}")
            return []
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips

    def _get_request_ip_probe_cache(self):
        if not hasattr(self, "_request_ip_probe_cache"):
            self._request_ip_probe_cache = {}
        return self._request_ip_probe_cache

    def _probe_show_request_ip(self, ip: str):
        cache = self._get_request_ip_probe_cache()
        now = time.time()
        cached = cache.get(ip)
        if cached and now - cached.get("checked_at", 0) <= self.SHOW_REQUEST_IP_PROBE_CACHE_TTL:
            return cached.get("usable", False)

        url = f"https://{ip}{self.SHOW_REQUEST_PROBE_PATH}"
        headers = {
            "Host": self.SHOW_REQUEST_HOST,
            "User-Agent": getattr(self, "ua", "Mozilla/5.0"),
        }
        status_code = None
        error = None
        try:
            # 只用 GET 探测 createV2 路由是否可达，不发送下单 POST。
            with httpx.Client(timeout=self.SHOW_REQUEST_IP_PROBE_TIMEOUT, http2=True, verify=False, trust_env=False) as client:
                resp = client.get(url, headers=headers)
                status_code = resp.status_code
                try:
                    resp.read()
                except Exception:
                    pass
            usable = status_code in self.SHOW_REQUEST_IP_USABLE_STATUS_CODES
        except Exception as e:
            usable = False
            error = str(e)

        cache[ip] = {
            "checked_at": now,
            "usable": usable,
            "status_code": status_code,
            "error": error,
        }
        if usable:
            logger.debug("请求 IP 探测可用: ip={} status={}".format(ip, status_code))
        else:
            logger.warning("请求 IP 探测不可用: ip={} status={} error={}".format(ip, status_code or "none", error or "none"))
        return usable

    def _seed_show_request_ip_pool(self):
        self._extend_request_ip_pool(self.SHOW_REQUEST_CANDIDATE_IPS)
        self._extend_request_ip_pool(self._resolve_request_ips(self.SHOW_REQUEST_HOST))

    def _pick_show_request_ip(self, current_ip: str = None, preferred_ips=None):
        self._seed_show_request_ip_pool()
        preferred = self._unique_request_ips(self._split_request_ips(preferred_ips))
        candidates = self._unique_request_ips(preferred + list(self.SHOW_REQUEST_VALIDATED_IPS) + self._request_ip_pool)
        candidates = [ip for ip in candidates if ip != current_ip]
        for ip in candidates:
            if self._probe_show_request_ip(ip):
                return ip
        return None

    def a(self, record: dict = None):
        record = record or {}
        hostname = record.get("host_header")
        if not hostname:
            hostname = urlparse(str(record.get("logical_url", ""))).hostname
        if not hostname and record.get("endpoint"):
            hostname = str(record["endpoint"]).split("/", 1)[0]

        if hostname != self.SHOW_REQUEST_HOST:
            logger.debug("429 不切换请求 IP: host={} 不是 {}".format(hostname or "unknown", self.SHOW_REQUEST_HOST))
            return None

        current_ip = record.get("custom_ip") or getattr(self, "_current_request_ip", None)
        self._extend_request_ip_pool(self._split_request_ips(current_ip))
        next_ip = self._pick_show_request_ip(current_ip)
        if not next_ip:
            logger.warning("429 后未找到可用的可切换请求 IP: host={} current_ip={}".format(hostname, current_ip or "未设置"))
            return None

        self._current_request_ip = next_ip
        logger.warning("429 后切换请求 IP: host={} {} -> {}".format(hostname, current_ip or "未设置", next_ip))
        return next_ip

    def _record_rate_limit(self, method: str, logical_url: str, response: httpx.Response, actual_url: str = None, custom_ip: str = None, host_header: str = None):
        try:
            response.read()
        except Exception:
            pass
        actual_url = actual_url or str(response.request.url if response.request else logical_url)
        parsed = urlparse(str(logical_url))
        endpoint = f"{parsed.netloc}{parsed.path}"
        cdn_info = self._extract_cdn_info(response.headers)
        self.rate_limit_events.append({"timestamp": time.time(), "method": method, "endpoint": endpoint, "provider": cdn_info["provider"], "zone": cdn_info["zone"]})
        summary = self._rate_limit_summary()
        record = {
            "event": "http_429_rate_limit",
            "local_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "epoch_ms": int(time.time() * 1000),
            "method": method,
            "endpoint": endpoint,
            "logical_url": self._redact_url(logical_url),
            "actual_url": self._redact_url(actual_url),
            "query_keys": [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)],
            "status_code": response.status_code,
            "reason_phrase": response.reason_phrase,
            "retry_after": response.headers.get("Retry-After"),
            "cdn": cdn_info,
            "last_known_cdn": self.last_cdn_info,
            "custom_ip": custom_ip,
            "host_header": host_header,
            "http_version": response.http_version,
            "response_headers": self._safe_header_dict(response.headers),
            "response_body_preview": response.text[:500],
            "summary": summary,
        }
        self.a(record)
        logger.warning("429限流诊断: {} endpoint={} cdn={}/{} retry_after={}".format(summary["classification"], endpoint, cdn_info["provider"], cdn_info["zone"], record["retry_after"]))
        logger.debug("429限流诊断详情: " + json.dumps(record, ensure_ascii=False, sort_keys=True))
        try:
            os.makedirs("bhyg_logs", exist_ok=True)
            file_name = time.strftime("429_diagnostics_%Y-%m-%d.jsonl", time.localtime())
            with open(os.path.join("bhyg_logs", file_name), "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        except Exception as e:
            logger.debug(f"429诊断日志写入失败: {e}")
    def _gen_risk_header(self):
        uid = self.uid
        buvid = self.buvid
        identify = urlencode(self._app_sign({"ts": int(time.time() * 1000)}))
        identify = quote(identify)
        _dist = [
            f"appkey/1d8b6e7d45233436",
            f"brand/{self.brand}",
            f"localBuvid/{buvid}",
            f"mVersion/296",
            f"mallVersion/{self.biliAppVersion}",
            f"model/{self.model}",
            f"osver/15",
            f"platform/h5",
            f"uid/{uid}",
            f"channel/1",
            f"deviceId/{buvid}",
            f"sLocale/zh_CN",
            f"cLocale/zh_CN",
            f"identify/{identify}" 
        ]
        return " ".join(_dist)

    def _app_sign(self,params: dict) -> dict:
        params.update({'appkey': "1d8b6e7d45233436"})
        params = dict(sorted(params.items()))
        query = urlencode(params)
        sign = hashlib.md5((query+"560c52ccd288fed045859ed18bffd973").encode()).hexdigest()
        params.update({'sign':sign})
        return params

    def gen_qr_url(self) -> Tuple[Optional[str], Optional[str]]:
        generate = self.get(
            "https://passport.bilibili.com/x/passport-login/web/qrcode/generate"
        )
        if generate["code"] == 0:
            url = generate["data"]["url"]
            key = generate["data"]["qrcode_key"]
        else:
            logger.error(generate)
            return None, None
        return url, key

    def check_qr_status(self, key) -> tuple[bool, bool]:
        '''
        return: (is_login, RETRY)
        '''
        url = (
                "https://passport.bilibili.com/x/passport-login/web/qrcode/poll?source=main-fe-header&qrcode_key="
                + key
            )
        check = self.get(url)
        if check["code"] != 0:
            logger.debug(check)
            logger.error(check["message"])
            return False, True
        if check["data"]["code"] == 0:
            self.check_login()
            return True, False
        elif check["data"]["code"] in [86101, 86090]:
            return False, True
        else:
            return False, False

    def check_login(self) -> Tuple[bool, Optional[dict]]:
        resp = self.get("https://api.bilibili.com/x/web-interface/nav")
        if resp["code"] == 0:
            self.uid = resp["data"]["mid"]
            self.username = resp["data"]["uname"]
            return True, resp["data"]
        else:
            return False, None


    def qrLogin(self): 
        warnings.warn(
            "This method is deprecated", DeprecationWarning
        )
        url, key = self.gen_qr_url()
        qr = qrcode.QRCode()
        qr.add_data(url)
        qr.print_ascii(invert=True)
        img = qr.make_image()
        img.show()
        while True:
            time.sleep(1)
            url = (
                "https://passport.bilibili.com/x/passport-login/web/qrcode/poll?source=main-fe-header&qrcode_key="
                + key
            )
            req = self.get(url)
            check = req["data"]
            if check["code"] == 0:
                break
            elif check["code"] == 86101:
                pass
            elif check["code"] == 86090:
                logger.info(check["message"])
            elif check["code"] == 86083:
                logger.error(check["message"])
                return False
            elif check["code"] == 86038:
                logger.error(check["message"])
                return False
            else:
                logger.error(check)
                return False
        self.uid = self.session.cookies.get("DedeUserID")
        return True

    def _print_session_header(self):
        cookies = self.session.cookies
        sessdata = cookies.get("SESSDATA")
        # rm sessdata
        cookies.pop("SESSDATA")
        cookies.update(
            {
                "SESSDATA": sessdata[:8]+"*"*16+ sessdata[-8:],
            }
        )
        logger.info(f"cookies: {cookies}")

        return self.session.headers, self.session.cookies

    def generate_token(self, projectId: int, screenId: int, skuId: int, count: int, orderType: int, ts=None) -> str:
        """
        生成Token
        """
        import base64
        
        map_orig = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+="
        map_real = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-."

        token = bytes([192]) # Header
        timestamp = int(time.time()) if ts is None else ts
        token += timestamp.to_bytes(4)
        token += projectId.to_bytes(4)
        token += screenId.to_bytes(4)
        token += orderType.to_bytes(1)
        token += count.to_bytes(2)
        token += skuId.to_bytes(4)

        token = base64.b64encode(token).decode()
        token = token.translate(str.maketrans(map_orig, map_real))
        return token

    def _get_env_data(self):
        return [
            0,
            0,
            random.randint(1000, 2000),
            random.randint(800, 1200),
            random.randint(1600, 2400),
            random.randint(800, 1200),
            0,
            0,
            random.randint(1600, 2400),
            random.randint(800, 1200),
            random.randint(1600, 2400),
            random.randint(10, 50),
            random.randint(100, 200),
            random.randint(50, 100),
            20,
            int(time.time() * 1000) % 256
        ]


    def generate_ctoken(self, m1=-1, m2=-1, m3=-1, m4=-1, m5=-1, m6=-1, m7=-1, m8=-1, m9=-1, touchend=-1, visibilitychange=-1, beforeunload=-1, timer=-1, ticket_collection_t=0, openWindow=-1):
        # COPYRIGHT 2026 ZianTT. ALL RIGHT RESERVED.
        # UNAUTHORIZED COPY AND COMMERCIALIZATION ARE NOT ALLOWED
        def m(t, env_data):
            idx1 = t % 16
            idx2 = (3 * t) % 16
            result = (env_data[idx1] + env_data[idx2] + 17 * t) & 255
            return result
        if touchend == -1:
            touchend = random.randint(30, 50)
        if visibilitychange == -1:
            visibilitychange = random.randint(10, 50)
        if beforeunload == -1:
            if openWindow != -1:
                beforeunload = openWindow
            else:
                beforeunload = random.randint(10, 50)
        if timer == -1:
            timer = random.randint(1, 10)
        env_data = self._get_env_data()
        if m1 == -1:
            m1 = m(1, env_data)
        if m2 == -1:
            m2 = m(2, env_data)
        if m3 == -1:
            m3 = m(3, env_data)
        if m4 == -1:
            m4 = m(4, env_data)
        if m5 == -1:
            m5 = m(5, env_data)
        if m6 == -1:
            m6 = m(6, env_data)
        if m7 == -1:
            m7 = m(7, env_data)
        if m8 == -1:
            m8 = m(8, env_data)
        if m9 == -1:
            m9 = m(9, env_data)
        token_bytes = b""
        data = {
            "m1": m1,
            "m2": m2,
            "m3": m3,
            "m4": m4,
            "m5": m5,
            "m6": m6,
            "m7": m7,
            "m8": m8,
            "m9": m9,
            "touchend": touchend,
            "visibilitychange": visibilitychange,
            "beforeunload": beforeunload,
            "timer": timer,
            "ticket_collection_t": ticket_collection_t,
        }
        token_bytes += data["m1"].to_bytes(1, byteorder='big')
        token_bytes += b"\x00"
        try:
            token_bytes += data["touchend"].to_bytes(1, byteorder='big')
        except OverflowError:
            token_bytes += b"\xff"
        token_bytes += b"\x00"
        token_bytes += data["m2"].to_bytes(1, byteorder='big')
        token_bytes += b"\x00"
        try:
            token_bytes += data["visibilitychange"].to_bytes(1, byteorder='big')
        except OverflowError:
            token_bytes += b"\xff"
        token_bytes += b"\x00"
        token_bytes += data["m3"].to_bytes(1, byteorder='big')
        token_bytes += b"\x00"
        token_bytes += data["m4"].to_bytes(1, byteorder='big')
        token_bytes += b"\x00"
        try:
            token_bytes += data["beforeunload"].to_bytes(1, byteorder='big')
        except OverflowError:
            token_bytes += b"\xff"
        token_bytes += b"\x00"
        token_bytes += data["m5"].to_bytes(1, byteorder='big')
        token_bytes += b"\x00"
        try:
            temp_timer = data["timer"].to_bytes(2, byteorder='big')
            token_bytes += temp_timer[0].to_bytes(1, byteorder='big')
            token_bytes += b"\x00"
            token_bytes += temp_timer[1].to_bytes(1, byteorder='big')
            token_bytes += b"\x00"
        except OverflowError:
            token_bytes += b"\xff\x00\xff\x00"
        try:
            temp_ticket_collection_t = int(data["ticket_collection_t"]).to_bytes(2, byteorder='big')
            token_bytes += temp_ticket_collection_t[0].to_bytes(1, byteorder='big')
            token_bytes += b"\x00"
            token_bytes += temp_ticket_collection_t[1].to_bytes(1, byteorder='big')
            token_bytes += b"\x00"
        except OverflowError:
            token_bytes += b"\xff\x00\xff\x00"
        token_bytes += data["m6"].to_bytes(1, byteorder='big')
        token_bytes += b"\x00"
        token_bytes += data["m7"].to_bytes(1, byteorder='big')
        token_bytes += b"\x00"
        token_bytes += data["m8"].to_bytes(1, byteorder='big')
        token_bytes += b"\x00"
        token_bytes += data["m9"].to_bytes(1, byteorder='big')
        token_bytes += b"\x00"
        # COPYRIGHT 2026 ZianTT. ALL RIGHT RESERVED.
        return base64.b64encode(token_bytes).decode('utf-8')

    def decode_ctoken(self, ctoken):
        import base64
        ctoken_bytes = base64.b64decode(ctoken)
        # data = {
        #     "touchend": ctoken_bytes[0],
        #     "scrollX": ctoken_bytes[2],
        #     "visibilitychange": ctoken_bytes[4],
        #     "scrollY": ctoken_bytes[6],
        #     "innerWidth": ctoken_bytes[8],
        #     "openWindow": ctoken_bytes[10],
        #     "innerHeight": ctoken_bytes[12],
        #     "outerWidth": ctoken_bytes[14],
        #     "timer": ctoken_bytes[16]*256 + ctoken_bytes[18],
        #     "ticket_collection_t": ctoken_bytes[20]*256 + ctoken_bytes[22],
        #     "outerHeight": ctoken_bytes[24],
        #     "screenX": ctoken_bytes[26],
        #     "screenY": ctoken_bytes[28],
        #     "screenWidth": ctoken_bytes[30]
        # }
        data = {
            "touchend": ctoken_bytes[0],
            "visibilitychange": ctoken_bytes[4],
            "openWindow": ctoken_bytes[10],
            "timer": ctoken_bytes[16]*256 + ctoken_bytes[18],
            "ticket_collection_t": ctoken_bytes[20]*256 + ctoken_bytes[22],
            "scrollX": ctoken_bytes[2],
            "scrollY": ctoken_bytes[6],
            "innerWidth": ctoken_bytes[8],
            "innerHeight": ctoken_bytes[12],
            "outerWidth": ctoken_bytes[14],
            "outerHeight": ctoken_bytes[24],
            "screenX": ctoken_bytes[26],
            "screenY": ctoken_bytes[28],
            "screenWidth": ctoken_bytes[30],
            "screenHeight": "unknown",
            "screenAvailWidth": "unknown"
        }
        return data

    def get(self, url: str, **kwargs) -> httpx.Response:
        try:
            resp = self.session.get(url, **kwargs)
        except Exception as e:
            return {"code": -114514,"message": f"请求失败：{e}","data": None}
        if resp.status_code == 429:
            self._record_rate_limit("GET", url, resp)
            return {"code": 429,"message": f"请求被限流：[{resp.status_code}]","data": None}
        if resp.status_code == 200:
            resp = resp.json()
            resp_content = {
                "code": resp["code"] if "code" in resp else resp["errno"] if "errno" in resp else None,
                "message": resp["message"] if "message" in resp else resp["msg"] if "msg" in resp else None,
                "data": resp["data"] if "data" in resp else None
            }
            return resp_content
        else:
            resp.read()
            resp_summary = resp.text if len(resp.text) < 30 else resp.text[:30] + "..."
            logger.error(f"非标状态码返回：[{resp.status_code}] {resp_summary}")
            content_type = resp.headers.get("Content-Type")
            if content_type and "application/json" in content_type:
                resp = resp.json()
                resp_content = {
                    "code": resp["code"] if "code" in resp else resp["errno"] if "errno" in resp else None,
                    "message": resp["message"] if "message" in resp else resp["msg"] if "msg" in resp else None,
                    "data": resp["data"] if "data" in resp else None
                }
            else:
                resp_content = {
                    "code": -resp.status_code,
                    "message": f"非标状态码返回：[{resp.status_code}] {resp_summary}",
                    "data": resp.text
                }
            return resp_content

            

    def post(self, url: str, **kwargs) -> httpx.Response:
        return_raw = kwargs.pop("raw", False)
        logical_url = url
        actual_url = url
        custom_ip = None
        host_header = None
        configured_ip = kwargs.pop("ip", None)
        self._extend_request_ip_pool(self._split_request_ips(configured_ip))
        if getattr(self, "_current_request_ip", None) is None and self._request_ip_pool:
            self._current_request_ip = self._request_ip_pool[0]
        try:
            if "createV2" in url and (configured_ip or getattr(self, "_current_request_ip", None)):
                configured_ips = self._split_request_ips(configured_ip)
                if not getattr(self, "_current_request_ip", None):
                    self._current_request_ip = self._pick_show_request_ip(preferred_ips=configured_ips)
                elif not self._probe_show_request_ip(self._current_request_ip):
                    self._current_request_ip = self._pick_show_request_ip(self._current_request_ip, configured_ips)
                if not self._current_request_ip:
                    return {"code": -114514,"message": "没有可用的下单 IP","data": None}
                hostname = urlparse(url).hostname
                custom_ip = self._current_request_ip
                host_header = hostname
                url = url.replace(hostname, custom_ip)
                actual_url = url
                headers = kwargs.pop("headers", {}) or {}
                headers["Host"] = hostname
                headers = httpx.Headers(headers)
                logger.debug(f"Request headers: {headers}")
                logger.debug(f"Request url: {url}")
                resp = self.session.post(url, headers=headers, **kwargs)
            else:
                resp = self.session.post(url, **kwargs)
        except Exception as e:
            return {"code": -114514,"message": f"请求失败：{e}","data": None}
        if resp.status_code == 429:
            self._record_rate_limit(
                "POST",
                logical_url,
                resp,
                actual_url=actual_url,
                custom_ip=custom_ip,
                host_header=host_header,
            )
        if return_raw:
            return resp
        if resp.status_code == 200:
            try:
                # logger.debug(f"Request headers: {resp.request.headers}")
                # logger.debug(f"Request body: {resp.request.content}")
                # logger.debug(f"Response headers: {resp.headers}")
                # logger.debug(f"Response content: {resp.text}")
                resp = resp.json()
                resp_content = {
                    "code": resp["code"] if "code" in resp else resp["errno"] if "errno" in resp else None,
                    "message": resp["message"] if "message" in resp else resp["msg"] if "msg" in resp else None,
                    "data": resp["data"] if "data" in resp else None
                }
                return resp_content
            except Exception as e:
                return {"code": -114514,"message": f"响应解析失败：{e}","data": None}
        elif resp.status_code == 429:
            resp.read()
            return {"code": 429,"message": f"请求被限流：[{resp.status_code}]","data": None}
        elif resp.status_code == 412:
            resp.read()
            return {"code": 412,"message": f"请求被风控：[{resp.status_code}]","data": None}
        else:
            resp.read()
            resp_summary = resp.text if len(resp.text) < 30 else resp.text[:30] + "..."
            logger.error(f"非标状态码返回：[{resp.status_code}] {resp_summary}")
            logger.debug(f"Response headers: {resp.headers}")  # 打印响应头
            logger.debug(f"Response content: {resp.text}")  # 打印响应内容
            content_type = resp.headers.get("Content-Type")
            if content_type and "application/json" in content_type:
                resp = resp.json()
                resp_content = {
                    "code": resp["code"] if "code" in resp else resp["errno"] if "errno" in resp else None,
                    "message": resp["message"] if "message" in resp else resp["msg"] if "msg" in resp else None,
                    "data": resp["data"] if "data" in resp else None
                }
            else:
                resp_content = {
                    "code": resp.status_code,
                    "message": None,
                    "data": resp.text
                }
            return resp_content

    def save(self):
        import pickle
        import base64
        self._headers = dict(self.session.headers)
        self._cookies = {}
        for i in list(self.session.cookies):
            self._cookies[i] = self.session.cookies.get(i, domain=".bilibili.com")
            if self._cookies[i] == None:
                self._cookies[i] = self.session.cookies.get(i, domain="show.bilibili.com")
            if self._cookies[i] == None:
                self._cookies[i] = self.session.cookies.get(i, domain="")
            if self._cookies[i] == None:
                self._cookies.pop(i)
        tmp_session = self.session
        self.session = None
        data = pickle.dumps(self)
        data = base64.b64encode(data).decode()
        self.session = tmp_session
        return data
    
    def load(self, data):
        import pickle
        import base64
        data = base64.b64decode(data)
        data = pickle.loads(data)
        self.__dict__.update(data.__dict__)
        self.session = httpx.Client(
            headers=self._headers,
            timeout=10,
            http2=True,
            event_hooks={
                "request": [self._on_request],
                "response": [self._on_response]
            },
            verify=False
        )
        self.session.cookies.update(self._cookies)
        self._getKeys()
        return
