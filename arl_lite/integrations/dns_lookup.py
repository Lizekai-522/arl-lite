"""arl_lite.integrations.dns_lookup

DNS 详细记录枚举 — 纯 stdlib(socket + struct)。

支持的记录类型:
- A / AAAA  IPv4 / IPv6 地址
- NS        名称服务器
- MX        邮件交换
- TXT       文本记录(含 SPF / DMARC / 域名验证)
- SOA       权威记录
- CNAME     别名

不依赖 dnspython — 用 socket 构造 DNS 包,自己解析。
"""
from __future__ import annotations

import logging
import random
import socket
import struct
from dataclasses import dataclass, field

log = logging.getLogger("arl_lite.integrations.dns_lookup")

# 记录类型
RTYPE_A = 1
RTYPE_NS = 2
RTYPE_CNAME = 5
RTYPE_SOA = 6
RTYPE_MX = 15
RTYPE_TXT = 16
RTYPE_AAAA = 28

# 类(internet)
CLASS_IN = 1


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rtype_name: str
    value: str
    ttl: int = 0
    extra: dict = field(default_factory=dict)  # MX preference / SOA primary/email

    def to_dict(self) -> dict:
        d = {"name": self.name, "type": self.rtype_name, "value": self.value, "ttl": self.ttl}
        d.update(self.extra)
        return d


def _encode_name(name: str) -> bytes:
    """域名 → DNS wire format 字节

    DNS 协议规定:
    - 每个 label 1-63 字符(不含前缀长度)
    - 总域名长度 ≤ 253 字符
    """
    if name is None:
        raise ValueError("name must not be None")
    if not isinstance(name, str):
        raise ValueError(f"name must be str (got {type(name).__name__})")
    if "\x00" in name:
        raise ValueError("name must not contain null byte")
    name = name.strip(".")
    if not name:
        return b"\x00"  # root label
    if len(name) > 253:
        raise ValueError(f"domain too long: {len(name)} > 253")
    parts = name.split(".")
    out = b""
    for p in parts:
        if not p:
            continue
        if len(p) > 63:
            raise ValueError(f"label too long: '{p[:20]}...' = {len(p)} > 63")
        encoded = p.encode("ascii", errors="replace")
        out += bytes([len(encoded)]) + encoded
    out += b"\x00"  # root label
    return out


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """DNS wire format → 域名,返回 (name, new_offset)"""
    labels = []
    jumped = False
    jumps = 0
    original_offset = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:  # 压缩指针
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            jumps += 1
            if jumps > 20:  # 自指/循环指针(恶意 DNS 响应)会无限跳,封顶
                break
            offset = pointer
            jumped = True
            continue
        # 长度字节后还有 length 字节的 label,所以需要 offset + 1 + length <= len
        if offset + 1 + length > len(data):
            break
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    name = ".".join(labels)
    return name, (original_offset if jumped else offset)


def _query(server: str, name: str, rtype: int, timeout: int = 5) -> tuple[bytes, int]:
    """发 DNS query,返回 (raw response bytes, 发出的 txid)

    返回 txid 让调用方校验响应——不校验的话,同网段攻击者抢答伪造
    响应即可投毒解析结果。
    """
    # 构造 query
    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # 标准 query
    question = _encode_name(name) + struct.pack(">HH", rtype, CLASS_IN)
    pkt = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (server, 53))
        resp, _ = sock.recvfrom(4096)
        return resp, txid
    finally:
        sock.close()


def _parse_response(data: bytes) -> tuple[int, int, list[DNSRecord]]:
    """解析 DNS response,返回 (rcode, ancount, records[])"""
    if not isinstance(data, (bytes, bytearray)):
        log.warning(f"data is not bytes: {type(data).__name__}")
        return 1, 0, []
    if len(data) < 12:
        log.debug(f"response too short: {len(data)} bytes")
        return 1, 0, []
    try:
        txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    except struct.error as e:
        log.warning(f"failed to unpack header: {e}")
        return 1, 0, []
    rcode = flags & 0x0F
    if rcode != 0:
        return rcode, 0, []

    records: list[DNSRecord] = []
    offset = 12
    # 跳过 question 段
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4  # type + class

    # 解析 answer
    for _ in range(ancount + nscount + arcount):
        if offset >= len(data):
            break
        try:
            name, offset = _decode_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            rtype_name = {RTYPE_A: "A", RTYPE_AAAA: "AAAA", RTYPE_NS: "NS",
                          RTYPE_CNAME: "CNAME", RTYPE_MX: "MX", RTYPE_TXT: "TXT",
                          RTYPE_SOA: "SOA"}.get(rtype, f"TYPE{rtype}")
            value = ""
            extra: dict = {}
            try:
                if rtype == RTYPE_A and len(rdata) == 4:
                    value = socket.inet_ntoa(rdata)
                elif rtype == RTYPE_AAAA and len(rdata) == 16:
                    value = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype in (RTYPE_NS, RTYPE_CNAME):
                    value, _ = _decode_name(data, offset - rdlength)
                elif rtype == RTYPE_MX and len(rdata) >= 3:
                    pref = struct.unpack(">H", rdata[:2])[0]
                    exchange, _ = _decode_name(data, offset - rdlength + 2)
                    value = exchange
                    extra = {"preference": pref}
                elif rtype == RTYPE_TXT:
                    # TXT 是 <len><data> 链
                    txt_parts = []
                    i = 0
                    while i < len(rdata):
                        l = rdata[i]
                        i += 1
                        if i + l <= len(rdata):
                            txt_parts.append(rdata[i:i + l].decode("utf-8", errors="replace"))
                        i += l
                    value = " ".join(txt_parts)
                elif rtype == RTYPE_SOA:
                    # SOA RDATA = mname + rname + 5×uint32
                    mname, rname_start = _decode_name(data, offset - rdlength)
                    rname, rname_end = _decode_name(data, rname_start)
                    if rname_end + 20 <= offset:
                        # 定时器必须从 rname 结束处取;从 mname 结束处取会把
                        # rname 的字节当成 serial(实测 serial 全错)
                        serial, refresh, retry, expire, minimum = struct.unpack(
                            ">IIIII", data[rname_end:rname_end + 20]
                        )
                    else:
                        serial = refresh = retry = expire = minimum = 0
                    value = f"mname={mname} rname={rname}"
                    extra = {"serial": serial, "refresh": refresh, "retry": retry,
                             "expire": expire, "minimum": minimum}
            except Exception as e:
                log.debug(f"parse rdata failed for type {rtype}: {e}")
                value = f"<unparseable {len(rdata)} bytes>"

            records.append(DNSRecord(
                name=name, rtype=rtype, rtype_name=rtype_name,
                value=value, ttl=ttl, extra=extra,
            ))
        except Exception as e:
            log.debug(f"parse record failed: {e}")
            break
    return rcode, ancount, records


def lookup(name: str, server: str | None = None, timeout: int = 5, should_stop=lambda: False) -> dict:
    """查询一个域名的所有常见记录

    Args:
        name: 域名(例 example.com)
        server: DNS server IP(默认 8.8.8.8)
        timeout: 超时秒

    Returns:
        dict: {rtype_name: [records...], "_status": "ok" | "error:..."}
    """
    # 防御:非 str / 空 / null byte / 超长 提前拒
    if not isinstance(name, str):
        return {"_status": f"error: name must be str (got {type(name).__name__})",
                "A": [], "AAAA": [], "NS": [], "MX": [],
                "TXT": [], "SOA": [], "CNAME": []}
    if not name or not name.strip():
        return {"_status": "error: empty name",
                "A": [], "AAAA": [], "NS": [], "MX": [],
                "TXT": [], "SOA": [], "CNAME": []}
    if "\x00" in name:
        return {"_status": "error: name contains null byte",
                "A": [], "AAAA": [], "NS": [], "MX": [],
                "TXT": [], "SOA": [], "CNAME": []}
    try:
        _encode_name(name)
    except ValueError as e:
        return {"_status": f"error: {e}",
                "A": [], "AAAA": [], "NS": [], "MX": [],
                "TXT": [], "SOA": [], "CNAME": []}
    if server is None:
        server = "8.8.8.8"
    result: dict[str, list] = {
        "A": [], "AAAA": [], "NS": [], "MX": [],
        "TXT": [], "SOA": [], "CNAME": [],
    }
    rtypes = [
        (RTYPE_A, "A"), (RTYPE_AAAA, "AAAA"),
        (RTYPE_NS, "NS"), (RTYPE_MX, "MX"),
        (RTYPE_TXT, "TXT"), (RTYPE_SOA, "SOA"),
        (RTYPE_CNAME, "CNAME"),
    ]
    errors = []
    for rtype, name_str in rtypes:
        if should_stop():
            raise InterruptedError("DNS lookup stopped")
        try:
            data, sent_txid = _query(server, name, rtype, timeout=timeout)
            # TXID 不匹配 = 抢答/伪造包,丢弃(同网段投毒防线)
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] != sent_txid:
                errors.append(f"{name_str}: txid mismatch (spoofed response dropped)")
                continue
            rcode, ancount, records = _parse_response(data)
            if rcode != 0:
                errors.append(f"{name_str}: rcode={rcode}")
                continue
            for r in records:
                if r.rtype_name in result:
                    result[r.rtype_name].append(r.to_dict())
        except socket.timeout:
            errors.append(f"{name_str}: timeout")
        except Exception as e:
            errors.append(f"{name_str}: {type(e).__name__}: {e}")
    if errors and not any(result.values()):
        result["_status"] = f"error: {'; '.join(errors)}"
    else:
        result["_status"] = "ok"
    return result
