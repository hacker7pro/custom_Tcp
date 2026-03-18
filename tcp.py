#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           TCP / UDP  Raw Packet Crafter                      ║
║  Full field control · 3-way handshake · Piggybacking         ║
║  TCP/IP options · Checksum override · Padding · Multi-send   ║
╚══════════════════════════════════════════════════════════════╝

  Bit · Byte · Hex quick reference
  ─────────────────────────────────
   4 bit  = <1 byte  =  1 hex char
   8 bit  =  1 byte  =  2 hex chars
  16 bit  =  2 bytes =  4 hex chars
  32 bit  =  4 bytes =  8 hex chars

  Modes
  ─────
  Q  Quick   — Src/Dst IP, ports, flags, payload only
               (everything else uses sensible defaults)
  E  Expert  — every field: IHL, DSCP/ECN, IP-ID, IP flags,
               fragment offset, IP options, TCP options,
               window, urgent pointer, checksum overrides,
               padding bytes
"""

import random, string, time
import scapy.all as scapy
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.l2 import Ether

# ─────────────────────────────────────────────────────────────
#  ANSI colour palette
# ─────────────────────────────────────────────────────────────

R  = "\033[0m"          # reset

# foreground
CYAN    = "\033[96m"    # section titles / rulers
YELLOW  = "\033[93m"    # field names / prompt labels
GREEN   = "\033[92m"    # ✓  ok / accepted / sent
RED     = "\033[91m"    # ✗  errors / warnings
MAGENTA = "\033[95m"    # →  arrows / defaults / values
BLUE    = "\033[94m"    # table borders / layout
WHITE   = "\033[97m"    # plain body text
ORANGE  = "\033[33m"    # ⚠  caution
GRAY    = "\033[90m"    # notes / secondary info

# bold variants
BCYAN   = "\033[1;96m"
BYELLOW = "\033[1;93m"
BGREEN  = "\033[1;92m"
BRED    = "\033[1;91m"
BMAGENTA= "\033[1;95m"
BWHITE  = "\033[1;97m"

# per-protocol accent colours
TCP_COL = "\033[96m"    # cyan  for TCP
UDP_COL = "\033[95m"    # magenta for UDP
IP_COL  = "\033[93m"    # yellow for IP

# helpers
def c(colour, text): return f"{colour}{text}{R}"

# ─────────────────────────────────────────────────────────────
#  Utility helpers
# ─────────────────────────────────────────────────────────────

def src_ip():
    try:    return scapy.get_if_addr(scapy.conf.iface)
    except: return "127.0.0.1"

def section(title):
    ruler = c(CYAN, "─" * 60)
    print(f"\n{ruler}\n  {c(BCYAN, title)}\n{ruler}")

def prompt(name, bits, def_hex, def_bin, def_dec, lo=None, hi=None, note=None):
    lo_s = f"  {c(GRAY,'min:')} {c(MAGENTA, f'h={hex(lo)[2:].zfill(bits//4 or 1)}  d={lo}')}" if lo is not None else ""
    hi_s = f"  {c(GRAY,'max:')} {c(MAGENTA, f'h={hex(hi)[2:].zfill(bits//4 or 1)}  d={hi}')}" if hi is not None else ""
    nt_s = f"\n  {c(GRAY,'note:')} {c(GRAY, note)}" if note else ""
    hdr  = f"\n{c(BYELLOW, name)}  {c(GRAY, f'[{bits} bit = {bits//8 or chr(60)+chr(49)} byte = {bits//4 or chr(60)+chr(49)} hex]')}"
    dfl  = f"  {c(GRAY,'default')} {c(MAGENTA,'→')} {c(MAGENTA, f'hex={def_hex}  bin={def_bin}  dec={def_dec}')}"
    return input(f"{hdr}\n{dfl}{lo_s}{hi_s}{nt_s}\n  {c(MAGENTA,'→')} ").strip()

def parse_num(s, default, name, lo=None, hi=None):
    if not s: return default
    s = s.strip().replace(" ", "").lower()
    for base in (10, 16, 2):
        try:
            v = int(s.replace("0x", ""), base) if base == 16 else int(s, base)
            if (lo is not None and v < lo) or (hi is not None and v > hi):
                print(f"  {c(ORANGE,'⚠')}  {c(ORANGE, f'{name}={v} is outside standard range → using anyway')}")
            return v
        except ValueError:
            pass
    print(f"  {c(RED,'✗')}  {c(RED, f'Invalid {name} → using default {default}')}")
    return default

def hex_to_bytes(s):
    clean = s.replace(" ", "").replace("0x", "")
    if not clean or not all(ch in "0123456789abcdefABCDEF" for ch in clean):
        return None
    try:    return bytes.fromhex(clean)
    except: return None

def ok(msg):   print(f"  {c(GREEN,'✓')}  {c(GREEN, msg)}")
def err(msg):  print(f"  {c(RED,'✗')}  {c(RED, msg)}")
def warn(msg): print(f"  {c(ORANGE,'⚠')}  {c(ORANGE, msg)}")
def arrow(msg):print(f"  {c(MAGENTA,'→')}  {c(WHITE, msg)}")

# ─────────────────────────────────────────────────────────────
#  Checksum computation
# ─────────────────────────────────────────────────────────────

def _ocs(data: bytes) -> int:
    if len(data) % 2: data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s = (s + w & 0xFFFF) + ((s + w) >> 16)
    return ~s & 0xFFFF

def calc_ip_checksum(ver, ihl, tos, tlen, ip_id, ff, ttl, proto, src_b, dst_b, opts=b''):
    h = bytearray([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + ip_id.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, 0, 0]) + src_b + dst_b + opts
    return _ocs(bytes(h))

def calc_tcp_checksum(src_b, dst_b, tcp_seg: bytes) -> int:
    pseudo = src_b + dst_b + b'\x00\x06' + len(tcp_seg).to_bytes(2,'big')
    return _ocs(pseudo + tcp_seg)

def calc_udp_checksum(src_b, dst_b, udp_seg: bytes) -> int:
    pseudo = src_b + dst_b + b'\x00\x11' + len(udp_seg).to_bytes(2,'big')
    r = _ocs(pseudo + udp_seg)
    return r if r != 0 else 0xFFFF

# ─────────────────────────────────────────────────────────────
#  Build raw wire bytes
# ─────────────────────────────────────────────────────────────

def build_ip_header(ver, ihl, tos, tlen, ip_id, ff, ttl, proto,
                    src_b, dst_b, opts, ck) -> bytes:
    h = bytearray([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + ip_id.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, (ck>>8)&0xFF, ck&0xFF]) + src_b + dst_b + opts
    return bytes(h)

def build_tcp_segment(sport, dport, seq, ack, data_off, flags, window, urg,
                      opts, payload, src_b, dst_b, custom_ck=None):
    seg = bytearray()
    seg += sport.to_bytes(2,'big') + dport.to_bytes(2,'big')
    seg += seq.to_bytes(4,'big')   + ack.to_bytes(4,'big')
    seg += bytes([(data_off<<4), flags])
    seg += window.to_bytes(2,'big') + b'\x00\x00' + urg.to_bytes(2,'big')
    seg += opts + payload
    ck = custom_ck if custom_ck is not None else calc_tcp_checksum(src_b, dst_b, bytes(seg))
    seg[16], seg[17] = (ck>>8)&0xFF, ck&0xFF
    return bytes(seg), ck

def build_udp_segment(sport, dport, payload, src_b, dst_b, custom_ck=None):
    length = 8 + len(payload)
    seg = bytearray()
    seg += sport.to_bytes(2,'big') + dport.to_bytes(2,'big')
    seg += length.to_bytes(2,'big') + b'\x00\x00' + payload
    ck = custom_ck if custom_ck is not None else calc_udp_checksum(src_b, dst_b, bytes(seg))
    seg[6], seg[7] = (ck>>8)&0xFF, ck&0xFF
    return bytes(seg), ck

# ─────────────────────────────────────────────────────────────
#  Network helpers
# ─────────────────────────────────────────────────────────────

def resolve_mac(dst, src):
    lmac = scapy.get_if_hwaddr(scapy.conf.iface)
    _, _, nh = scapy.conf.route.route(dst)
    target = dst if nh in ("0.0.0.0", src) else nh
    print(f"  {c(CYAN,'Resolving MAC for')} {c(YELLOW, target)} ...")
    try:
        mac = scapy.getmacbyip(target)
        if mac:
            ok(f"MAC: {c(GREEN, mac)}")
            return lmac, mac
    except Exception as e:
        err(f"MAC error: {e}")
    arrow("fallback to broadcast ff:ff:ff:ff:ff:ff")
    return lmac, "ff:ff:ff:ff:ff:ff"

def send_frame(ip_bytes, lmac, rmac, timeout, wait_reply=True):
    pkt = Ether(src=lmac, dst=rmac, type=0x0800) / Raw(load=ip_bytes)
    if wait_reply:
        return scapy.srp(pkt, timeout=timeout, verbose=0, iface=scapy.conf.iface)
    scapy.sendp(pkt, verbose=0, iface=scapy.conf.iface)
    return None, None

# ─────────────────────────────────────────────────────────────
#  Common input helpers
# ─────────────────────────────────────────────────────────────

def ask_padding():
    raw = input(f"\n  {c(YELLOW,'Add padding bytes?')} (y/n) [{c(MAGENTA,'n')}]: ").strip().lower()
    if raw not in ('y','yes'): return b''
    cnt = max(1, min(200, int(input(f"  {c(YELLOW,'Count')}  [{c(MAGENTA,'4')}]:       ") or 4)))
    b   = int((input(f"  {c(YELLOW,'Byte hex')}  [{c(MAGENTA,'00')}]:   ").strip() or "00"), 16) & 0xFF
    arrow(f"{cnt} × 0x{b:02X}")
    return bytes([b]) * cnt

def ask_send_params():
    count    = int(input(f"\n  {c(YELLOW,'Packets')}     [{c(MAGENTA,'1')}]:   ") or 1)
    interval = float(input(f"  {c(YELLOW,'Interval s')}  [{c(MAGENTA,'1')}]:   ") or 1)
    timeout  = float(input(f"  {c(YELLOW,'Timeout s')}   [{c(MAGENTA,'2')}]:   ") or 2)
    if count == 1 or interval >= 0.5:
        wait = input(f"  {c(YELLOW,'Wait for reply?')} (y/n) [{c(MAGENTA,'y')}]: ").strip().lower() not in ('n','no')
    else:
        arrow(f"High-speed burst: {c(ORANGE,'fire-and-forget')} (no per-packet reply wait)")
        wait = False
    return count, interval, timeout, wait

# ─────────────────────────────────────────────────────────────
#  Payload generator
# ─────────────────────────────────────────────────────────────

def gen_payload(n, ptype, pat=None):
    if n <= 0: return b''
    if ptype == 1:
        return bytes(random.randint(0,1) for _ in range(n))
    if ptype == 2:
        return bytes(random.randint(0,255) for _ in range(n))
    if ptype == 3:
        b = pat if isinstance(pat, int) else random.randint(0,255)
        arrow(f"repeat 0x{b:02x}")
        return bytes([b]) * n
    if ptype == 4:
        buf, v = bytearray(), 0
        for _ in range(n):
            buf.append(v % 256)
            op = random.choice(['+2','*2','/2','nop'])
            if   op == '+2':       v += 2
            elif op == '*2':       v *= 2
            elif op == '/2' and v: v //= 2
        return bytes(buf)
    if ptype == 5:
        pool = (string.ascii_letters + string.digits + string.punctuation).encode()
        return bytes(random.choice(pool) for _ in range(n))
    if ptype == 6:
        bs = ''.join(random.choice('01') for _ in range(n*8))
        for _ in range(random.randint(2,6)):
            p  = random.randint(0, max(0, n*8-100))
            rl = random.randint(16, 80)
            bs = bs[:p] + random.choice('01')*rl + bs[p+rl:]
        bs  = bs[:n*8]
        buf = bytearray(int(bs[j:j+8].ljust(8,'0'), 2) for j in range(0, len(bs), 8))
        arrow("bit stream pattern")
        return bytes(buf)
    if ptype == 7:
        pair = random.choice([(0x55,0xAA),(0xA5,0x5A),(0xFF,0x00),
                               (0xF0,0x0F),(0xCC,0x33),(0xAB,0xCD)])
        arrow(f"hex-pair {pair[0]:02X} {pair[1]:02X} repeating")
        return bytes(pair[j%2] for j in range(n))
    if ptype == 8:
        raw = input(f"  {c(YELLOW,'Custom hex payload')}: ").strip()
        b   = hex_to_bytes(raw)
        if not b:
            err("Invalid hex → falling back to random bytes")
            return bytes(random.randint(0,255) for _ in range(n))
        b = b[:n] if len(b) >= n else (b * ((n+len(b)-1)//len(b)))[:n]
        arrow(f"custom payload {len(b)}B")
        return b
    return b''

def _tbl(rows):
    """Print a coloured 2-column table from list of (key, val) strings."""
    w = max(len(k) for k,_ in rows) + 2
    top = c(BLUE, "  ┌" + "─"*w + "┬" + "─"*44 + "┐")
    bot = c(BLUE, "  └" + "─"*w + "┴" + "─"*44 + "┘")
    print(top)
    for k, v in rows:
        key  = c(YELLOW, f" {k} ".ljust(w))
        val  = c(WHITE,  f" {v}".ljust(44))
        pipe = c(BLUE, "│")
        print(f"  {pipe}{key}{pipe}{val}{pipe}")
    print(bot)

def ask_payload(label="Payload", default_len=64):
    print(f"\n  {c(BYELLOW, label + ' size')}")
    _tbl([("Enter byte count", "or 0 for empty payload")])
    raw = input(f"  {c(YELLOW,'Size B')}  [{c(MAGENTA, str(default_len))}]: ").strip()
    try:    n = max(0, int(raw)) if raw else default_len
    except: n = default_len
    if n == 0:
        arrow("empty payload")
        return b''

    print(f"\n  {c(BYELLOW,'Payload type')}")
    _tbl([
        ("1", "random bits     (0 or 1 per byte)"),
        ("2", "random hex      (0x00–0xFF random bytes)"),
        ("3", "repeat pattern  (single byte repeated)"),
        ("4", "arithmetic      (incrementing with random ops)"),
        ("5", "mixed           (printable ASCII + symbols)"),
        ("6", "bit stream      (random runs of 0s and 1s)"),
        ("7", "hex pair        (two-byte alternating pattern)"),
        ("8", "custom hex      (you supply the bytes)"),
    ])
    try:    ptype = int(input(f"  {c(MAGENTA,'→')} [5]: ").strip() or 5); ptype = ptype if 1<=ptype<=8 else 5
    except: ptype = 5

    pat = None
    if ptype == 3:
        try:    pat = int((input(f"  {c(YELLOW,'Pattern byte hex')} [{c(MAGENTA,'AA')}]: ").strip() or "AA"), 16) & 0xFF
        except: pat = 0xAA

    pl = gen_payload(n, ptype, pat)
    ok(f"{len(pl)}B payload ready")
    return pl

# ─────────────────────────────────────────────────────────────
#  IP header  (shared by TCP + UDP)
# ─────────────────────────────────────────────────────────────

class IPCfg:
    __slots__ = ('version','ihl','tos','ttl','proto','ip_id','ff',
                 'src','dst','SRC','DST','opts','opts_for_ck',
                 'custom_ck','ck_val')

def ask_ip_header(expert, proto_num, proto_name):
    c_obj = IPCfg()
    c_obj.version = 4
    c_obj.ff      = 0x0000
    c_obj.opts    = b''
    c_obj.opts_for_ck = b''

    section(f"IP Header  {c(GRAY,'(fields in wire order)')}")

    print(f"\n  {c(BYELLOW,'IP header layout')}")
    _tbl([
        ("Byte  0",    "Version (4 bit) + IHL (4 bit)"),
        ("Byte  1",    "DSCP (6 bit) + ECN (2 bit)  =  TOS byte"),
        ("Byte  2–3",  "Total Length  ← auto-computed at send time"),
        ("Byte  4–5",  "Identification (IP-ID)"),
        ("Byte  6–7",  "IP Flags (3 bit) + Fragment Offset (13 bit)"),
        ("Byte  8",    "TTL"),
        ("Byte  9",    "Protocol"),
        ("Byte 10–11", "Header Checksum"),
        ("Byte 12–15", "Source IP"),
        ("Byte 16–19", "Destination IP"),
        ("Byte 20+",   "IP Options  (present only when IHL > 5)"),
    ])

    print(f"\n  {c(CYAN,'Version')} {c(GRAY,'=')} {c(MAGENTA,'4')}  {c(GRAY,'(IPv4 — fixed)')}")

    # ── IHL ──────────────────────────────────────────────────
    ihl = parse_num(
        prompt("IHL", 4, "5","0101","5", lo=5, hi=15,
               note="5=20B (no options)  6=24B  7=28B … 15=60B  |  "
                    "options budget = (IHL-5)×4 bytes  |  max options = 40B"),
        5, "IHL")
    opts_budget = (ihl - 5) * 4
    arrow(f"IHL={c(MAGENTA,str(ihl))}  header={c(MAGENTA,str(ihl*4)+'B')}  options budget={c(MAGENTA,str(opts_budget)+'B')}")

    # ── DSCP / ECN ───────────────────────────────────────────
    if expert:
        dscp = parse_num(prompt("DSCP", 6, "00","000000","0", lo=0, hi=63,
                                note="QoS / traffic class  |  0 = best-effort"), 0, "DSCP")
        ecn  = parse_num(prompt("ECN",  2, "00","00","0",     lo=0, hi=3,
                                note="0=Not-ECT  1=ECT(1)  2=ECT(0)  3=CE"),    0, "ECN")
        c_obj.tos = (dscp<<2) | ecn
        arrow(f"TOS byte = {c(MAGENTA,'0x'+f'{c_obj.tos:02X}')}  (DSCP={dscp}  ECN={ecn})")
    else:
        c_obj.tos = 0

    print(f"\n  {c(CYAN,'Total Length')}  {c(GRAY,'→')}  {c(WHITE,'auto-computed at send time  (IHL×4 + transport + payload)')}")

    # ── IP-ID ────────────────────────────────────────────────
    if expert:
        ip_id = parse_num(
            prompt("ID", 16, "0000","0"*16,"0", lo=0, hi=65535,
                   note="2 bytes  |  fragment identification / packet tracking"),
            0, "ID")
    else:
        ip_id = random.randint(0, 0xFFFF)
        print(f"\n  {c(CYAN,'IP-ID')}  {c(GRAY,'→')}  {c(MAGENTA,'0x'+f'{ip_id:04X}')}  {c(GRAY,'(random — set in Expert mode)')}")
    c_obj.ip_id = ip_id

    # ── IP Flags + Fragment Offset ────────────────────────────
    if expert:
        print(f"\n  {c(BYELLOW,'IP Flags')}  {c(GRAY,'[3 bit]')}")
        _tbl([
            ("bit2", "Reserved — must be 0"),
            ("bit1", "DF  Don't Fragment"),
            ("bit0", "MF  More Fragments"),
        ])
        print(f"  {c(GRAY,'Common values:')}  {c(MAGENTA,'0')} = none  {c(MAGENTA,'2')} = DF  {c(MAGENTA,'1')} = MF")
        ip_flags = parse_num(prompt("IP Flags", 3, "0","000","0", lo=0, hi=7), 0, "IP Flags")
        frag_off = parse_num(
            prompt("Fragment Offset", 13, "0000","0"*13,"0", lo=0, hi=8191,
                   note="units of 8 bytes  |  0 = not fragmented"), 0, "Fragment Offset")
        c_obj.ff = (ip_flags << 13) | frag_off
        arrow(f"Flags+FragOff field = {c(MAGENTA,'0x'+f'{c_obj.ff:04X}')}")
    else:
        c_obj.ff = 0x0000

    # ── TTL ──────────────────────────────────────────────────
    c_obj.ttl = parse_num(
        prompt("TTL", 8, "40","01000000","64", lo=1, hi=255,
               note="1 byte  |  64=Linux  128=Windows  255=max"),
        64, "TTL")

    # ── Protocol ─────────────────────────────────────────────
    proto_colour = TCP_COL if proto_num == 6 else UDP_COL
    print(f"\n  {c(CYAN,'Protocol')} {c(GRAY,'=')} {c(proto_colour, str(proto_num))}  {c(GRAY,'('+proto_name+' — set by mode selection)')}")
    c_obj.proto = proto_num

    # ── Src / Dst IP ─────────────────────────────────────────
    raw_src = input(f"\n  {c(YELLOW,'Src IP')}  [{c(MAGENTA, src_ip())}]: ").strip() or src_ip()
    raw_dst = input(f"  {c(YELLOW,'Dst IP')}  [{c(MAGENTA,'192.168.1.1')}]: ").strip() or "192.168.1.1"

    try:    c_obj.SRC = scapy.inet_aton(raw_src);  c_obj.src = raw_src
    except: warn(f"Invalid Src IP → using {src_ip()}"); c_obj.src = src_ip(); c_obj.SRC = scapy.inet_aton(c_obj.src)
    try:    c_obj.DST = scapy.inet_aton(raw_dst);  c_obj.dst = raw_dst
    except: warn("Invalid Dst IP → using 192.168.1.1"); c_obj.dst="192.168.1.1"; c_obj.DST=scapy.inet_aton(c_obj.dst)

    # ── IP Options ───────────────────────────────────────────
    c_obj.opts = b''
    if expert:
        print(f"\n  {c(BYELLOW,'IP Options')}")
        _tbl([
            ("budget",  f"(IHL-5)×4 = {opts_budget}B  ({opts_budget*2} hex chars)"),
            ("step",    "4B  (must be multiple of 4)"),
            ("max",     "40B  (80 hex chars)  IHL max = 15"),
            ("padding", "non-multiples → auto zero-padded to next 4B"),
        ])
        if opts_budget == 0:
            arrow(f"options budget = {c(ORANGE,'0B')}  (IHL=5 → no options space)")
        elif input(f"  {c(YELLOW,'Add IP options?')} (y/n) [{c(MAGENTA,'n')}]: ").strip().lower() in ('y','yes'):
            h = input(f"  {c(YELLOW,'Options hex')} {c(GRAY,'→')} ").strip().replace(" ","").replace("0x","").upper()
            if h and all(ch in "0123456789ABCDEF" for ch in h):
                try:
                    raw_opts = bytes.fromhex(h)
                    if len(raw_opts) > opts_budget:
                        warn(f"Exceeds budget {opts_budget}B (got {len(raw_opts)}B) → truncating")
                        raw_opts = raw_opts[:opts_budget]
                    pad = (4 - len(raw_opts) % 4) % 4
                    if pad:
                        raw_opts += b'\x00' * pad
                        arrow(f"Auto-padded +{pad}B → {len(raw_opts)}B: {c(MAGENTA, raw_opts.hex().upper())}")
                    else:
                        ok(f"Accepted {len(raw_opts)}B: {c(GREEN, h)}")

                    needed_ihl = 5 + len(raw_opts) // 4
                    if needed_ihl != ihl:
                        warn(f"IHL conflict: you set IHL={ihl} ({ihl*4}B) but "
                             f"{len(raw_opts)}B options require IHL={needed_ihl} ({needed_ihl*4}B)")
                        print(f"  {c(MAGENTA,'1.')}  {c(GREEN,'Auto-adjust IHL to')} {c(BGREEN, str(needed_ihl))}  {c(GRAY,'(correct packet)')}")
                        print(f"  {c(MAGENTA,'2.')}  {c(ORANGE,'Keep IHL='+str(ihl))}  {c(GRAY,'(intentional mismatch on wire)')}")
                        ch = input(f"  {c(MAGENTA,'→')} [1]: ").strip() or "1"
                        if ch == "2":
                            arrow(f"Keeping IHL={c(ORANGE,str(ihl))} ({ihl*4}B)  {c(GRAY,'— intentional mismatch')}")
                        else:
                            ihl = needed_ihl
                            arrow(f"IHL auto-adjusted to {c(GREEN,str(ihl))} ({ihl*4}B)")
                    else:
                        ihl = needed_ihl

                    c_obj.opts = raw_opts
                    ok(f"IHL={ihl}  ({ihl*4}B total = 20B base + {len(c_obj.opts)}B options)  "
                       f"{c(GRAY,'[IHL max=15=60B]')}")
                except Exception as e:
                    err(f"Error: {e} → no options added")
            else:
                err("Invalid hex → no options added")

    c_obj.ihl       = ihl
    c_obj.custom_ck = False
    c_obj.ck_val    = 0
    return c_obj

def ask_ip_checksum(cfg, transport_len, expert):
    tlen      = cfg.ihl*4 + transport_len
    opts_info = f"{len(cfg.opts)}B = {cfg.opts.hex().upper()}" if cfg.opts else "none"
    preview   = calc_ip_checksum(cfg.version, cfg.ihl, cfg.tos, tlen, cfg.ip_id,
                                  cfg.ff, cfg.ttl, cfg.proto, cfg.SRC, cfg.DST, cfg.opts)

    ruler = c(CYAN, "─" * 40)
    print(f"\n  {ruler}  {c(BCYAN,'IP Checksum / Total Length')}  {ruler[:20]}")
    print(f"     {c(YELLOW,'Total Length')}  = {c(MAGENTA, str(tlen)+'B')}  ({c(MAGENTA,'0x'+f'{tlen:04X}')})")
    print(f"     {c(YELLOW,'IHL')}={c(MAGENTA,str(cfg.ihl))} ({cfg.ihl*4}B)  "
          f"{c(YELLOW,'options')}={c(MAGENTA,opts_info)}")
    print(f"     {c(YELLOW,'calc checksum')} = {c(BGREEN,'0x'+f'{preview:04x}')}")

    cs_in = input(f"\n  {c(YELLOW,'Desired IP checksum')}  "
                  f"[{c(MAGENTA,'Enter')}={c(GREEN,'auto')}  |  or type custom hex]: ").strip()
    if cs_in:
        try:
            cfg.ck_val    = int(cs_in.replace("0x",""), 16) & 0xFFFF
            cfg.custom_ck = True
            arrow(f"custom {c(MAGENTA,'0x'+f'{cfg.ck_val:04x}')}")
            return
        except:
            err("Invalid → using calculated value")

    cfg.custom_ck = False
    if expert and len(cfg.opts) > 0:
        ck_scope = input(f"  {c(YELLOW,'Options bytes for checksum')}  "
                         f"[0–{len(cfg.opts)}, {c(MAGENTA,'Enter')} = all {len(cfg.opts)}B]: ").strip()
        try:    n_ck = max(0, min(len(cfg.opts), int(ck_scope))) if ck_scope else len(cfg.opts)
        except: n_ck = len(cfg.opts)
        cfg.opts_for_ck = cfg.opts[:n_ck]
        cfg.ck_val = calc_ip_checksum(cfg.version, cfg.ihl, cfg.tos, tlen, cfg.ip_id,
                                       cfg.ff, cfg.ttl, cfg.proto,
                                       cfg.SRC, cfg.DST, cfg.opts_for_ck)
        arrow(f"{c(BGREEN,'0x'+f'{cfg.ck_val:04x}')}  (20B base + {n_ck}B opts used)")
    else:
        cfg.opts_for_ck = cfg.opts
        cfg.ck_val      = preview
        arrow(c(BGREEN,'0x'+f'{cfg.ck_val:04x}'))

# ─────────────────────────────────────────────────────────────
#  TCP flags
# ─────────────────────────────────────────────────────────────

TCP_FLAGS = {'FIN':0x01,'SYN':0x02,'RST':0x04,'PSH':0x08,
             'ACK':0x10,'URG':0x20,'ECE':0x40,'CWR':0x80}

def flags_str(b):
    return '|'.join(k for k,v in TCP_FLAGS.items() if b & v) or 'NONE'

def ask_tcp_flags():
    print(f"\n  {c(BYELLOW,'TCP Flags')}  {c(GRAY,'[8 bit = 1 byte = 2 hex]')}")
    _tbl([
        (" 1", "SYN      Initiate connection  → 3-way handshake"),
        (" 2", "ACK      Acknowledge  (+ optional piggyback data)"),
        (" 3", "PSH+ACK  Push data to application immediately"),
        (" 4", "SYN+ACK  Server handshake reply"),
        (" 5", "FIN      Graceful connection close"),
        (" 6", "FIN+ACK  Graceful close with acknowledgement"),
        (" 7", "RST      Reset / abort connection"),
        (" 8", "URG+ACK  Urgent data pointer active"),
        (" 9", "custom   hex / binary / flag names"),
    ])
    print(f"\n  {c(GRAY,'Custom entry examples:')}")
    print(f"    {c(GRAY,'hex    →')}  {c(MAGENTA,'0x18   0x02')}")
    print(f"    {c(GRAY,'binary →')}  {c(MAGENTA,'00011000   00000010')}")
    print(f"    {c(GRAY,'names  →')}  {c(MAGENTA,'PSH ACK   SYN   FIN ACK')}")

    choice = input(f"\n  {c(MAGENTA,'→')} [1]: ").strip() or "1"
    presets = {
        "1":(0x02,"SYN"),     "2":(0x10,"ACK"),
        "3":(0x18,"PSH+ACK"), "4":(0x12,"SYN+ACK"),
        "5":(0x01,"FIN"),     "6":(0x11,"FIN+ACK"),
        "7":(0x04,"RST"),     "8":(0x30,"URG+ACK"),
    }
    if choice in presets:
        fb, name = presets[choice]
        arrow(f"{c(BGREEN,name)}  hex={c(MAGENTA,'0x'+f'{fb:02X}')}  bin={c(MAGENTA,f'{fb:08b}')}  dec={c(MAGENTA,str(fb))}")
        return fb, name

    raw = input(f"  {c(YELLOW,'Custom flags')} (0x.. / binary / names): ").strip()
    fb  = 0
    try:
        if raw.lower().startswith("0x"):
            fb = int(raw, 16) & 0xFF
        elif all(ch in '01' for ch in raw.replace(" ","")):
            fb = int(raw.replace(" ",""), 2) & 0xFF
        else:
            for part in raw.upper().split():
                fb |= TCP_FLAGS.get(part, 0)
    except:
        fb = 0x02
    name = flags_str(fb)
    arrow(f"{c(BGREEN,name)}  hex={c(MAGENTA,'0x'+f'{fb:02X}')}  bin={c(MAGENTA,f'{fb:08b}')}  dec={c(MAGENTA,str(fb))}")
    return fb, name

# ─────────────────────────────────────────────────────────────
#  TCP options (expert only)
# ─────────────────────────────────────────────────────────────

def ask_tcp_options(expert):
    if not expert: return b''
    print(f"\n  {c(BYELLOW,'TCP Options')}  {c(GRAY,'(expert)')}")
    _tbl([
        ("min",     "4B  (8 hex chars)   step = 4B"),
        ("max",     "40B  (80 hex chars)  auto zero-padded"),
    ])
    print(f"\n  {c(GRAY,'Common TCP options (hex):')}")
    print(f"    {c(YELLOW,'MSS 1460')}          {c(GRAY,'→')}  {c(MAGENTA,'02 04 05 B4')}")
    print(f"    {c(YELLOW,'NOP')}               {c(GRAY,'→')}  {c(MAGENTA,'01 01 01 01')}  {c(GRAY,'(4×NOP pad)')}")
    print(f"    {c(YELLOW,'Window Scale ×128')} {c(GRAY,'→')}  {c(MAGENTA,'03 03 07 00')}  {c(GRAY,'(+ NOP pad)')}")
    print(f"    {c(YELLOW,'SACK Permitted')}    {c(GRAY,'→')}  {c(MAGENTA,'04 02 01 01')}  {c(GRAY,'(+ NOP pad)')}")
    print(f"    {c(YELLOW,'Timestamp (zeros)')} {c(GRAY,'→')}  {c(MAGENTA,'08 0A 00 00 00 00 00 00 00 00')}")

    if input(f"\n  {c(YELLOW,'Add TCP options?')} (y/n) [{c(MAGENTA,'n')}]: ").strip().lower() not in ('y','yes'):
        return b''
    h = input(f"  {c(YELLOW,'Options hex')} {c(GRAY,'→')} ").strip().replace(" ","").replace("0x","").upper()
    if not h or not all(ch in "0123456789ABCDEF" for ch in h):
        err("Invalid hex → no options")
        return b''
    try:
        opts = bytes.fromhex(h)
        pad  = (4 - len(opts) % 4) % 4
        if pad:
            opts += b'\x00' * pad
            arrow(f"Auto-padded +{pad}B → {len(opts)}B: {c(MAGENTA, opts.hex().upper())}")
        else:
            ok(f"Accepted {len(opts)}B: {c(GREEN, h)}")
        return opts
    except Exception as e:
        err(f"Error: {e} → no options")
        return b''

# ─────────────────────────────────────────────────────────────
#  Three-way handshake
# ─────────────────────────────────────────────────────────────

def three_way_handshake(cfg, sport, dport, isn, window, tcp_opts,
                        piggyback, padding, timeout, wait, lmac, rmac):
    data_off = 5 + len(tcp_opts)//4

    # ── Step 1 / SYN ─────────────────────────────────────────
    print(f"\n  {c(CYAN,'┌─')} {c(BGREEN,'[1/3]')}  {c(TCP_COL,'SYN')}  "
          f"{c(YELLOW,cfg.src)}:{c(MAGENTA,str(sport))} {c(WHITE,'→')} "
          f"{c(YELLOW,cfg.dst)}:{c(MAGENTA,str(dport))}  "
          f"{c(GRAY,'seq=')+c(MAGENTA,str(isn))}")

    syn_seg, syn_ck = build_tcp_segment(
        sport, dport, isn, 0, data_off, 0x02,
        window, 0, tcp_opts, b'', cfg.SRC, cfg.DST)
    syn_tlen = cfg.ihl*4 + len(syn_seg)
    syn_ipck = calc_ip_checksum(cfg.version, cfg.ihl, cfg.tos, syn_tlen, cfg.ip_id,
                                 cfg.ff, cfg.ttl, 6, cfg.SRC, cfg.DST, cfg.opts_for_ck)
    syn_hdr  = build_ip_header(cfg.version, cfg.ihl, cfg.tos, syn_tlen, cfg.ip_id,
                                cfg.ff, cfg.ttl, 6, cfg.SRC, cfg.DST, cfg.opts, syn_ipck)
    ans, _   = send_frame(syn_hdr + syn_seg, lmac, rmac, timeout, wait_reply=True)
    print(f"  {c(CYAN,'│')}  {c(GREEN,'✓')}  {c(GREEN,'SYN sent')}  "
          f"TCPck={c(MAGENTA,'0x'+f'{syn_ck:04X}')}  IPck={c(MAGENTA,'0x'+f'{syn_ipck:04X}')}")

    # ── Step 2 / parse SYN+ACK ───────────────────────────────
    server_isn = None
    if ans:
        r = ans[0][1]
        if TCP in r:
            rt  = r[TCP]
            rf  = flags_str(int(rt.flags))
            fcc = GREEN if (int(rt.flags) & 0x12 == 0x12) else ORANGE
            print(f"  {c(CYAN,'│')}  {c(BLUE,'←')}  "
                  f"{c(YELLOW,r[IP].src)}:{c(MAGENTA,str(rt.sport))}  "
                  f"flags={c(fcc,rf)}  seq={c(MAGENTA,str(rt.seq))}  ack={c(MAGENTA,str(rt.ack))}")
            if int(rt.flags) & 0x12 == 0x12:
                server_isn = rt.seq
                print(f"  {c(CYAN,'│')}  {c(GREEN,'✓')}  {c(GREEN,'SYN+ACK received')}  "
                      f"server_ISN={c(MAGENTA,str(server_isn))}")
            else:
                warn(f"Expected SYN+ACK — got {rf}")
        else:
            err("Reply has no TCP layer")
    else:
        err("No reply to SYN (timeout)")

    status = c(GREEN,'✓ SYN+ACK received') if server_isn is not None else c(RED,'✗ no SYN+ACK — continuing anyway')
    print(f"  {c(CYAN,'└─')} {c(BGREEN,'[2/3]')}  {status}")

    # ── Step 3 / ACK (+ optional piggyback) ──────────────────
    my_seq  = (isn + 1) % (2**32)
    ack_num = ((server_isn + 1) % (2**32)) if server_isn is not None else 1
    ack_id  = (cfg.ip_id + 1) % 65536

    if piggyback:
        ack_flags = 0x18
        label     = c(TCP_COL,"PSH+ACK") + c(GRAY,"  (piggybacked data)")
        label_raw = "PSH+ACK"
    else:
        ack_flags = 0x10
        label     = c(TCP_COL,"ACK")
        label_raw = "ACK"

    print(f"\n  {c(CYAN,'┌─')} {c(BGREEN,'[3/3]')}  {label}")
    print(f"  {c(CYAN,'│')}  seq={c(MAGENTA,str(my_seq))}  ack={c(MAGENTA,str(ack_num))}"
          + (f"  payload={c(MAGENTA,str(len(piggyback))+'B')}" if piggyback else ""))

    ack_seg, ack_ck = build_tcp_segment(
        sport, dport, my_seq, ack_num, data_off, ack_flags,
        window, 0, tcp_opts, piggyback + padding, cfg.SRC, cfg.DST)
    ack_tlen = cfg.ihl*4 + len(ack_seg)
    ack_ipck = calc_ip_checksum(cfg.version, cfg.ihl, cfg.tos, ack_tlen, ack_id,
                                 cfg.ff, cfg.ttl, 6, cfg.SRC, cfg.DST, cfg.opts_for_ck)
    ack_hdr  = build_ip_header(cfg.version, cfg.ihl, cfg.tos, ack_tlen, ack_id,
                                cfg.ff, cfg.ttl, 6, cfg.SRC, cfg.DST, cfg.opts, ack_ipck)
    ans2, _  = send_frame(ack_hdr + ack_seg, lmac, rmac, timeout, wait_reply=wait)
    print(f"  {c(CYAN,'│')}  {c(GREEN,'✓')}  {c(GREEN,label_raw+' sent')}  "
          f"TCPck={c(MAGENTA,'0x'+f'{ack_ck:04X}')}  IPck={c(MAGENTA,'0x'+f'{ack_ipck:04X}')}")

    if wait and ans2:
        r2 = ans2[0][1]
        if TCP in r2:
            rt2 = r2[TCP]
            print(f"  {c(CYAN,'│')}  {c(BLUE,'←')}  "
                  f"flags={c(GREEN,flags_str(int(rt2.flags)))}  "
                  f"seq={c(MAGENTA,str(rt2.seq))}  ack={c(MAGENTA,str(rt2.ack))}")
            rdata = bytes(rt2.payload)
            if rdata:
                print(f"  {c(CYAN,'│')}  {c(BLUE,'←')}  "
                      f"server data {c(MAGENTA,str(len(rdata))+'B')}: {c(GRAY,rdata[:64].hex())}")
        else:
            print(f"  {c(CYAN,'│')}  {c(BLUE,'←')}  reply (no TCP layer)")
    elif wait:
        print(f"  {c(CYAN,'│')}  {c(RED,'✗')}  no reply to ACK (timeout)")

    print(f"  {c(CYAN,'└─')} {c(BGREEN,'✓')}  {c(BGREEN,'Three-way handshake complete')}\n")
    return my_seq, ack_num

# ─────────────────────────────────────────────────────────────
#  TCP mode
# ─────────────────────────────────────────────────────────────

def mode_tcp(expert):
    cfg = ask_ip_header(expert, proto_num=6, proto_name="TCP")

    section(f"TCP Header  {c(GRAY,'(fields in wire order)')}")
    print(f"\n  {c(BYELLOW,'TCP header layout')}")
    _tbl([
        ("Byte  0–1",  "Source Port"),
        ("Byte  2–3",  "Destination Port"),
        ("Byte  4–7",  "Sequence Number"),
        ("Byte  8–11", "Acknowledgement Number"),
        ("Byte 12",    "Data Offset (4b) + Reserved (3b) + NS (1b)"),
        ("Byte 13",    "CWR ECE URG ACK PSH RST SYN FIN  flags"),
        ("Byte 14–15", "Window Size"),
        ("Byte 16–17", "Checksum"),
        ("Byte 18–19", "Urgent Pointer"),
        ("Byte 20+",   "TCP Options  (if Data Offset > 5)"),
    ])
    print(f"  {c(CYAN,'Data Offset')}  {c(GRAY,'→')}  {c(WHITE,'auto-computed  (5 + TCP_options_len/4)')}")

    sport = parse_num(
        prompt("Src Port", 16, "1234","0001001000110100","4660",
               lo=0, hi=65535, note="2 bytes  |  ephemeral range: 1024–65535"),
        4660, "Src Port")

    dport = parse_num(
        prompt("Dst Port", 16, "0050","0000000001010000","80",
               lo=0, hi=65535,
               note="2 bytes  |  80=HTTP  443=HTTPS  22=SSH  53=DNS  8080=alt-HTTP"),
        80, "Dst Port")

    flags_byte, flag_name = ask_tcp_flags()
    is_syn = (flags_byte == 0x02)

    seq = parse_num(
        prompt("Sequence Number", 32,
               "00000000","0"*32, str(random.randint(1000,0xFFFF0000)),
               lo=0, hi=2**32-1,
               note="4 bytes  |  ISN (Initial Sequence Number) for SYN"),
        random.randint(1000, 0xFFFF0000) if is_syn else 0, "Seq")

    ack_n = 0
    if not is_syn or expert:
        ack_n = parse_num(
            prompt("Acknowledgement Number", 32, "00000000","0"*32,"0",
                   lo=0, hi=2**32-1,
                   note="4 bytes  |  next expected byte from remote  |  0 if ACK not set"),
            0, "Ack")

    window = 65535
    if expert:
        window = parse_num(
            prompt("Window Size", 16, "FFFF","1"*16,"65535",
                   lo=0, hi=65535,
                   note="2 bytes  |  receive buffer space advertised to sender"),
            65535, "Window")

    urg_ptr = 0
    if expert and (flags_byte & 0x20):
        urg_ptr = parse_num(
            prompt("Urgent Pointer", 16, "0000","0"*16,"0",
                   lo=0, hi=65535,
                   note="2 bytes  |  offset to last urgent byte (only valid when URG set)"),
            0, "Urgent Pointer")

    tcp_opts = ask_tcp_options(expert)
    data_off = 5 + len(tcp_opts)//4
    print(f"\n  {c(CYAN,'Data Offset')}  {c(GRAY,'→')}  "
          f"{c(MAGENTA,str(data_off))}  ({c(MAGENTA,str(data_off*4)+'B')} TCP header)")

    # TCP checksum override (expert only)
    tcp_custom_ck, tcp_ck_val = False, None
    if expert:
        ck_in = input(f"\n  {c(YELLOW,'TCP checksum')}  "
                      f"[{c(MAGENTA,'Enter')}={c(GREEN,'auto')}  |  or type custom hex]: ").strip()
        if ck_in:
            try:
                tcp_ck_val    = int(ck_in.replace("0x",""), 16) & 0xFFFF
                tcp_custom_ck = True
                arrow(f"custom {c(MAGENTA,'0x'+f'{tcp_ck_val:04X}')}")
            except:
                err("Invalid → auto")

    # ── SYN → 3-way handshake ────────────────────────────────
    if is_syn:
        section("Three-Way Handshake")
        print(f"""
  {c(TCP_COL,'SYN')}  {c(GREEN,'──►')}  {c(GRAY,'(this host initiates)')}
       {c(GREEN,'◄──')}  {c(TCP_COL,'SYN+ACK')}  {c(GRAY,'(server replies)')}
  {c(TCP_COL,'ACK')}  {c(GREEN,'──►')}  {c(GRAY,'(connection established)')}

  {c(BYELLOW,'Piggybacking concept:')}
    {c(WHITE,'Sending application data on the third ACK (PSH+ACK) avoids')}
    {c(WHITE,'an extra round-trip.  ACK flag is upgraded automatically.')}
        """)
        piggyback = b''
        if input(f"  {c(YELLOW,'Piggyback data on the final ACK?')} (y/n) [{c(MAGENTA,'n')}]: ").strip().lower() in ('y','yes'):
            print(f"  {c(GRAY,'(PSH+ACK will be used automatically)')}")
            piggyback = ask_payload("Piggybacked payload", default_len=32)

        padding = ask_padding()
        count, interval, timeout, wait = ask_send_params()
        est_transport = data_off*4 + len(piggyback) + len(padding)
        ask_ip_checksum(cfg, est_transport, expert)
        lmac, rmac = resolve_mac(cfg.dst, cfg.src)
        for i in range(count):
            if i > 0: time.sleep(interval)
            if count > 1:
                print(f"\n  {c(CYAN,'──')} {c(BWHITE,f'Handshake attempt {i+1}/{count}')} {c(CYAN,'──')}")
            cfg.ip_id = (cfg.ip_id + i*2) % 65536
            three_way_handshake(cfg, sport, dport, (seq + i) % (2**32),
                                window, tcp_opts, piggyback, padding,
                                timeout, wait, lmac, rmac)
        ok("Done.")
        return

    # ── Non-SYN: direct send ─────────────────────────────────
    payload = b''
    if flags_byte & 0x08:
        print(f"\n  {c(YELLOW,'PSH flag set')} — payload expected")
        payload = ask_payload("TCP payload")
    else:
        if input(f"\n  {c(YELLOW,'Add payload to this segment?')} (y/n) [{c(MAGENTA,'n')}]: ").strip().lower() in ('y','yes'):
            payload = ask_payload("TCP payload")
            if payload and flags_byte == 0x10:
                flags_byte |= 0x08
                flag_name   = flags_str(flags_byte)
                arrow(f"Piggybacking: flags upgraded to {c(BGREEN,flag_name)}")

    padding = ask_padding()
    ask_ip_checksum(cfg, data_off*4 + len(payload) + len(padding), expert)
    count, interval, timeout, wait = ask_send_params()
    lmac, rmac = resolve_mac(cfg.dst, cfg.src)

    print(f"\n  {c(BWHITE,'Sending')} {c(MAGENTA,str(count))} "
          f"{c(TCP_COL,'TCP')} [{c(BGREEN,flag_name)}] "
          f"packet(s) {c(WHITE,'→')} "
          f"{c(YELLOW,cfg.dst)}:{c(MAGENTA,str(dport))}\n")

    for i in range(count):
        cur_seq = (seq + i * max(1, len(payload))) % (2**32)
        cur_ack = (ack_n + i) % (2**32)
        cur_id  = (cfg.ip_id + i) % 65536

        seg, tcp_ck = build_tcp_segment(
            sport, dport, cur_seq, cur_ack, data_off, flags_byte,
            window, urg_ptr, tcp_opts, payload + padding, cfg.SRC, cfg.DST,
            tcp_ck_val if tcp_custom_ck else None)

        tlen = cfg.ihl*4 + len(seg)
        ipck = cfg.ck_val if cfg.custom_ck else calc_ip_checksum(
            cfg.version, cfg.ihl, cfg.tos, tlen, cur_id, cfg.ff,
            cfg.ttl, 6, cfg.SRC, cfg.DST, cfg.opts_for_ck)
        hdr  = build_ip_header(cfg.version, cfg.ihl, cfg.tos, tlen, cur_id, cfg.ff,
                                cfg.ttl, 6, cfg.SRC, cfg.DST, cfg.opts, ipck)

        ans, _ = send_frame(hdr + seg, lmac, rmac, timeout, wait)
        print(f"  {c(CYAN,f'[{i+1:>4}/{count}]')}  "
              f"{c(YELLOW,cfg.src)}:{c(MAGENTA,str(sport))} {c(WHITE,'→')} "
              f"{c(YELLOW,cfg.dst)}:{c(MAGENTA,str(dport))}"
              f"  {c(BGREEN,flag_name)}"
              f"  seq={c(MAGENTA,str(cur_seq))}"
              f"  ack={c(MAGENTA,str(cur_ack))}"
              f"  pay={c(MAGENTA,str(len(payload))+'B')}"
              f"  TCPck={c(MAGENTA,'0x'+f'{tcp_ck:04X}')}"
              f"  IPck={c(MAGENTA,'0x'+f'{ipck:04X}')}"
              f"  ID={c(GRAY,'0x'+f'{cur_id:04X}')}")

        if wait:
            if ans:
                r = ans[0][1]
                if TCP in r:
                    rt = r[TCP]
                    print(f"       {c(MAGENTA,'↳')}  {c(BLUE,'←')}  "
                          f"{c(YELLOW,r[IP].src)}:{c(MAGENTA,str(rt.sport))}"
                          f"  flags={c(GREEN,flags_str(int(rt.flags)))}"
                          f"  seq={c(MAGENTA,str(rt.seq))}"
                          f"  ack={c(MAGENTA,str(rt.ack))}")
                    rdata = bytes(rt.payload)
                    if rdata:
                        print(f"          {c(BLUE,'data')} {c(MAGENTA,str(len(rdata))+'B')}: "
                              f"{c(GRAY,rdata[:48].hex())}")
                else:
                    print(f"       {c(MAGENTA,'↳')}  reply (no TCP layer)")
            else:
                print(f"       {c(MAGENTA,'↳')}  {c(RED,'no reply (timeout)')}")

        if i < count-1: time.sleep(interval)
    print(f"\n  {c(BGREEN,'Done.')}")

# ─────────────────────────────────────────────────────────────
#  UDP mode
# ─────────────────────────────────────────────────────────────

def mode_udp(expert):
    cfg = ask_ip_header(expert, proto_num=17, proto_name="UDP")

    section(f"UDP Header  {c(GRAY,'(fields in wire order)')}")
    print(f"\n  {c(BYELLOW,'UDP header layout')}")
    _tbl([
        ("Byte  0–1", "Source Port"),
        ("Byte  2–3", "Destination Port"),
        ("Byte  4–5", "Length  ← auto-computed  (8 + payload bytes)"),
        ("Byte  6–7", "Checksum"),
    ])
    print(f"  {c(CYAN,'Length')}  {c(GRAY,'→')}  {c(WHITE,'auto-computed at send time')}")

    sport = parse_num(
        prompt("Src Port", 16, "1234","0001001000110100","4660",
               lo=0, hi=65535, note="2 bytes  |  ephemeral range: 1024–65535"),
        4660, "Src Port")

    dport = parse_num(
        prompt("Dst Port", 16, "0035","0000000000110101","53",
               lo=0, hi=65535,
               note="2 bytes  |  53=DNS  67=DHCP  123=NTP  161=SNMP  514=syslog"),
        53, "Dst Port")

    # UDP checksum
    udp_custom_ck, udp_ck_val = False, None
    print(f"\n  {c(BYELLOW,'UDP Checksum')}")
    _tbl([
        ("1", "auto     correct checksum over pseudo-header+payload"),
        ("2", "disable  0x0000  (RFC 768 — receiver ignores check)"),
        ("3", "custom   you supply the 2-byte value"),
    ])
    ck_ch = input(f"  {c(MAGENTA,'→')} [1]: ").strip() or "1"
    if ck_ch == "2":
        udp_ck_val, udp_custom_ck = 0x0000, True
        arrow(f"checksum {c(ORANGE,'disabled')} (0x0000)")
    elif ck_ch == "3":
        ck_in = input(f"  {c(YELLOW,'Custom checksum hex')}: ").strip()
        try:
            udp_ck_val    = int(ck_in.replace("0x",""), 16) & 0xFFFF
            udp_custom_ck = True
            arrow(f"custom {c(MAGENTA,'0x'+f'{udp_ck_val:04X}')}")
        except:
            err("Invalid → auto")

    payload = ask_payload("UDP payload", default_len=32)
    padding = ask_padding()
    ask_ip_checksum(cfg, 8 + len(payload) + len(padding), expert)
    count, interval, timeout, wait = ask_send_params()
    lmac, rmac = resolve_mac(cfg.dst, cfg.src)

    print(f"\n  {c(BWHITE,'Sending')} {c(MAGENTA,str(count))} "
          f"{c(UDP_COL,'UDP')} packet(s) "
          f"{c(WHITE,'→')} "
          f"{c(YELLOW,cfg.dst)}:{c(MAGENTA,str(dport))}\n")

    for i in range(count):
        cur_id = (cfg.ip_id + i) % 65536
        seg, udp_ck = build_udp_segment(
            sport, dport, payload + padding, cfg.SRC, cfg.DST,
            udp_ck_val if udp_custom_ck else None)

        tlen = cfg.ihl*4 + len(seg)
        ipck = cfg.ck_val if cfg.custom_ck else calc_ip_checksum(
            cfg.version, cfg.ihl, cfg.tos, tlen, cur_id, cfg.ff,
            cfg.ttl, 17, cfg.SRC, cfg.DST, cfg.opts_for_ck)
        hdr  = build_ip_header(cfg.version, cfg.ihl, cfg.tos, tlen, cur_id, cfg.ff,
                                cfg.ttl, 17, cfg.SRC, cfg.DST, cfg.opts, ipck)

        ans, _ = send_frame(hdr + seg, lmac, rmac, timeout, wait)
        print(f"  {c(CYAN,f'[{i+1:>4}/{count}]')}  "
              f"{c(YELLOW,cfg.src)}:{c(MAGENTA,str(sport))} {c(WHITE,'→')} "
              f"{c(YELLOW,cfg.dst)}:{c(MAGENTA,str(dport))}"
              f"  pay={c(MAGENTA,str(len(payload))+'B')}"
              f"  UDPck={c(MAGENTA,'0x'+f'{udp_ck:04X}')}"
              f"  IPck={c(MAGENTA,'0x'+f'{ipck:04X}')}"
              f"  ID={c(GRAY,'0x'+f'{cur_id:04X}')}")

        if wait:
            if ans:
                r = ans[0][1]
                if UDP in r:
                    ru = r[UDP]
                    print(f"       {c(MAGENTA,'↳')}  {c(BLUE,'←')}  "
                          f"{c(YELLOW,r[IP].src)}:{c(MAGENTA,str(ru.sport))}"
                          f"  len={c(MAGENTA,str(ru.len))}")
                    rdata = bytes(ru.payload)
                    if rdata:
                        print(f"          {c(BLUE,'data')} {c(MAGENTA,str(len(rdata))+'B')}: "
                              f"{c(GRAY,rdata[:48].hex())}")
                else:
                    print(f"       {c(MAGENTA,'↳')}  reply (no UDP layer)")
            else:
                print(f"       {c(MAGENTA,'↳')}  {c(RED,'no reply (timeout)')}")

        if i < count-1: time.sleep(interval)
    print(f"\n  {c(BGREEN,'Done.')}")

# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def print_banner():
    banner_lines = [
        "╔══════════════════════════════════════════════════════════════╗",
        "║           TCP / UDP  Raw Packet Crafter                      ║",
        "║  Full field control · 3-way handshake · Piggybacking         ║",
        "║  TCP/IP options · Checksum override · Padding · Multi-send   ║",
        "╚══════════════════════════════════════════════════════════════╝",
    ]
    for line in banner_lines:
        print(c(BCYAN, line))

    print(f"""
  {c(BYELLOW,'Bit · Byte · Hex quick reference')}
  {c(CYAN,'─────────────────────────────────')}
   {c(MAGENTA,'4 bit')}  {c(GRAY,'=')} {c(WHITE,'<1 byte')}  {c(GRAY,'=')}  {c(WHITE,'1 hex char')}
   {c(MAGENTA,'8 bit')}  {c(GRAY,'=')} {c(WHITE,' 1 byte')}  {c(GRAY,'=')}  {c(WHITE,'2 hex chars')}
  {c(MAGENTA,'16 bit')}  {c(GRAY,'=')} {c(WHITE,' 2 bytes')} {c(GRAY,'=')}  {c(WHITE,'4 hex chars')}
  {c(MAGENTA,'32 bit')}  {c(GRAY,'=')} {c(WHITE,' 4 bytes')} {c(GRAY,'=')}  {c(WHITE,'8 hex chars')}""")

def main():
    print_banner()

    section("Mode")
    print(f"""
  {c(BGREEN,'Q')}  {c(BWHITE,'Quick')}   {c(WHITE,'Src/Dst IP, ports, flags, payload only')}
             {c(GRAY,'All other fields use sensible defaults')}

  {c(BGREEN,'E')}  {c(BWHITE,'Expert')}  {c(WHITE,'Every field:')}
             {c(GRAY,'IHL · DSCP/ECN · IP-ID · IP Flags · Frag Offset')}
             {c(GRAY,'IP Options · TCP Options · Window · Urgent Pointer')}
             {c(GRAY,'Checksum overrides · Padding bytes')}
""")
    expert = input(f"  {c(MAGENTA,'→')} [{c(MAGENTA,'Q')}]: ").strip().upper() == "E"
    arrow(f"{'Expert' if expert else 'Quick'} mode selected")

    section("Protocol")
    print(f"""
  {c(BGREEN,'1')}  {c(TCP_COL,'TCP')}   {c(WHITE,'Flags · 3-way handshake · Piggybacking · TCP options')}
  {c(BGREEN,'2')}  {c(UDP_COL,'UDP')}   {c(WHITE,'Stateless · optional checksum disable')}
""")
    proto_ch = input(f"  {c(MAGENTA,'→')} [{c(MAGENTA,'1')}]: ").strip() or "1"
    if proto_ch == "2":
        mode_udp(expert)
    else:
        mode_tcp(expert)

if __name__ == "__main__":
    try:    main()
    except KeyboardInterrupt: print(f"\n\n  {c(ORANGE,'Stopped.')}")
    except Exception as e:    print(f"\n  {c(RED,'Error:')} {e}")
