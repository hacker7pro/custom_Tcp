#!/usr/bin/env python3
"""
TCP/UDP Raw Packet Crafter
  • Quick mode  : src/dst IP, ports, flags, payload — everything else is sane default
  • Expert mode : full control over every IP/TCP/UDP field, options, checksums, padding
  • SYN flag    : triggers automatic 3-way handshake
  • ACK / PSH+ACK : piggybacking data offer
"""

import random, string, time
import scapy.all as scapy
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.l2 import Ether

# ─────────────────────────────────────────────────────────────────────────────
# Tiny helpers
# ─────────────────────────────────────────────────────────────────────────────

def local_ip():
    try:    return scapy.get_if_addr(scapy.conf.iface)
    except: return "127.0.0.1"

def ask(prompt_str, default):
    val = input(f"  {prompt_str} [{default}]: ").strip()
    return val if val else str(default)

def ask_int(prompt_str, default, lo=None, hi=None):
    raw = ask(prompt_str, default)
    try:
        if raw.lower().startswith("0x"):  v = int(raw, 16)
        elif raw.lower().startswith("0b"): v = int(raw, 2)
        else:                              v = int(raw)
        if lo is not None and v < lo: print(f"    ↳ Note: {v} < min {lo}, using anyway")
        if hi is not None and v > hi: print(f"    ↳ Note: {v} > max {hi}, using anyway")
        return v
    except ValueError:
        print(f"    ↳ Invalid → using default {default}")
        return int(str(default).replace("0x","") if str(default).startswith("0x") else default) if str(default).isdigit() else default

def ask_ip(prompt_str, default):
    raw = ask(prompt_str, default)
    try:
        scapy.inet_aton(raw); return raw
    except:
        print(f"    ↳ Invalid IP → using {default}"); return default

def ask_yes(prompt_str, default="n"):
    raw = ask(prompt_str + " (y/n)", default)
    return raw.lower() in ("y", "yes")

def hex_to_bytes(s):
    clean = s.replace(" ","").replace("0x","")
    if not clean: return None
    try:    return bytes.fromhex(clean)
    except: return None

# ─────────────────────────────────────────────────────────────────────────────
# Checksum computation
# ─────────────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────────────
# Build raw wire bytes
# ─────────────────────────────────────────────────────────────────────────────

def build_ip_header(ver, ihl, tos, tlen, ip_id, ff, ttl, proto, src_b, dst_b, opts, ck) -> bytes:
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

# ─────────────────────────────────────────────────────────────────────────────
# Network I/O
# ─────────────────────────────────────────────────────────────────────────────

def resolve_mac(dst_ip, src_ip):
    lmac = scapy.get_if_hwaddr(scapy.conf.iface)
    _, _, nh = scapy.conf.route.route(dst_ip)
    target = dst_ip if nh in ("0.0.0.0", src_ip) else nh
    print(f"  → ARP resolving {target} ...", end=" ", flush=True)
    try:
        mac = scapy.getmacbyip(target)
        if mac: print(mac); return lmac, mac
    except Exception as e: print(f"failed ({e})")
    print("ff:ff:ff:ff:ff:ff (broadcast fallback)")
    return lmac, "ff:ff:ff:ff:ff:ff"

def sr_frame(ip_bytes, lmac, rmac, timeout):
    pkt = Ether(src=lmac, dst=rmac, type=0x0800) / Raw(load=ip_bytes)
    return scapy.srp(pkt, timeout=timeout, verbose=0, iface=scapy.conf.iface)

# ─────────────────────────────────────────────────────────────────────────────
# Payload generator
# ─────────────────────────────────────────────────────────────────────────────

def gen_payload(n, ptype, pat=None):
    if n <= 0: return b''
    if ptype == 1: return bytes(random.randint(0,255) for _ in range(n))
    if ptype == 2:
        pool = (string.ascii_letters + string.digits).encode()
        return bytes(random.choice(pool) for _ in range(n))
    if ptype == 3:
        b = pat if isinstance(pat,int) else 0xAA
        return bytes([b]) * n
    if ptype == 4:
        raw = ask("  Custom hex payload", "deadbeef")
        b = hex_to_bytes(raw)
        if not b: print("    ↳ Invalid → random"); return bytes(random.randint(0,255) for _ in range(n))
        b = b[:n] if len(b) >= n else (b * ((n+len(b)-1)//len(b)))[:n]
        return b
    return bytes(random.randint(0,255) for _ in range(n))

def ask_payload(default_len=64):
    n = ask_int("Payload size (bytes)", default_len, lo=0)
    if n == 0: return b''
    print("    Type: 1=random-bytes  2=ascii  3=repeat-byte  4=custom-hex")
    try:    ptype = int(ask("    Type", "1")); ptype = ptype if 1<=ptype<=4 else 1
    except: ptype = 1
    pat = None
    if ptype == 3:
        raw = ask("    Repeat byte (hex)", "AA")
        try:    pat = int(raw, 16) & 0xFF
        except: pat = 0xAA
    pl = gen_payload(n, ptype, pat)
    print(f"    ↳ {len(pl)}B payload ready")
    return pl

# ─────────────────────────────────────────────────────────────────────────────
# TCP flags
# ─────────────────────────────────────────────────────────────────────────────

TCP_FLAGS = {'FIN':0x01,'SYN':0x02,'RST':0x04,'PSH':0x08,
             'ACK':0x10,'URG':0x20,'ECE':0x40,'CWR':0x80}

def flags_str(b):
    return '|'.join(k for k,v in TCP_FLAGS.items() if b & v) or 'NONE'

def ask_tcp_flags():
    print("""
  ── TCP Flags ──────────────────────────────────────────
   1) SYN          initiates connection → 3-way handshake
   2) ACK          acknowledge (+ optional piggyback data)
   3) PSH+ACK      push data to application immediately
   4) SYN+ACK      server handshake reply
   5) FIN          graceful connection close
   6) FIN+ACK      graceful close with acknowledgement
   7) RST          reset / abort connection
   8) URG+ACK      urgent data pointer active
   9) Custom       hex / binary / flag names""")
    choice = ask("  Select", "1")
    presets = {
        "1":(0x02,"SYN"),     "2":(0x10,"ACK"),
        "3":(0x18,"PSH+ACK"), "4":(0x12,"SYN+ACK"),
        "5":(0x01,"FIN"),     "6":(0x11,"FIN+ACK"),
        "7":(0x04,"RST"),     "8":(0x30,"URG+ACK"),
    }
    if choice in presets:
        fb, name = presets[choice]
        print(f"  → {name}  (0x{fb:02X}  b={fb:08b})")
        return fb, name
    raw = ask("  Flags (0x12 / 00010010 / SYN ACK)", "0x02")
    fb = 0
    try:
        if raw.startswith("0x") or raw.startswith("0X"): fb = int(raw, 16) & 0xFF
        elif all(c in '01' for c in raw.replace(" ","")): fb = int(raw.replace(" ",""), 2) & 0xFF
        else:
            for part in raw.upper().split(): fb |= TCP_FLAGS.get(part, 0)
    except: fb = 0x02
    name = flags_str(fb)
    print(f"  → {name}  (0x{fb:02X}  b={fb:08b})")
    return fb, name

# ─────────────────────────────────────────────────────────────────────────────
# IP config dataclass
# ─────────────────────────────────────────────────────────────────────────────

class IPConfig:
    __slots__ = ('version','ihl','tos','ttl','proto','ip_id','ff',
                 'src','dst','SRC','DST','opts','custom_ck','ck_val')

def ask_ip_fields(expert, proto):
    c = IPConfig()
    c.version, c.ff, c.opts = 4, 0x0000, b''

    print("\n  ── IP Header  (fields in wire order) ─────────────────")
    print("  ┌──────────┬──────────────────────────────────────────┐")
    print("  │ Byte 0   │ Version(4b) + IHL(4b)                   │")
    print("  │ Byte 1   │ DSCP(6b) + ECN(2b)  = TOS               │")
    print("  │ Byte 2-3 │ Total Length  (auto = IHL*4 + payload)  │")
    print("  │ Byte 4-5 │ Identification                          │")
    print("  │ Byte 6-7 │ IP Flags(3b) + Fragment Offset(13b)     │")
    print("  │ Byte 8   │ TTL                                     │")
    print("  │ Byte 9   │ Protocol                                │")
    print("  │ Byte 10-11│ Header Checksum                        │")
    print("  │ Byte 12-15│ Source IP                              │")
    print("  │ Byte 16-19│ Destination IP                         │")
    print("  │ Byte 20+  │ IP Options  (if IHL > 5)               │")
    print("  └──────────┴──────────────────────────────────────────┘")

    # ── Version (fixed 4) ────────────────────────────────────────────────────
    # shown for awareness; not asked since IPv6 is out of scope
    print(f"\n  Version = 4  (IPv4, fixed)")

    # ── IHL — ask FIRST so user understands options budget ───────────────────
    print("\n  IHL (Internet Header Length) — 4-bit field, units of 4 bytes")
    print("    5=20B (no options)  6=24B  7=28B  8=32B … 15=60B")
    print("    Set IHL first; IP options must fit within IHL*4 - 20 bytes")
    if expert:
        ihl_in = ask_int("IHL", 5, lo=5, hi=15)
        opts_budget = (ihl_in - 5) * 4
        print(f"    ↳ IHL={ihl_in} → header={ihl_in*4}B → options budget={opts_budget}B")
    else:
        ihl_in    = 5
        opts_budget = 0
        print(f"    ↳ IHL=5 (20B, no options) — use Expert mode to change")

    # ── DSCP / ECN (TOS byte) ────────────────────────────────────────────────
    if expert:
        dscp = ask_int("DSCP [0-63]  (QoS / traffic class, 0=best-effort)", 0, lo=0, hi=63)
        ecn  = ask_int("ECN  [0-3]   (0=Not-ECT  1=ECT1  2=ECT0  3=CE)",   0, lo=0, hi=3)
        c.tos = (dscp << 2) | ecn
        print(f"    ↳ TOS byte = 0x{c.tos:02X}  (DSCP={dscp} ECN={ecn})")
    else:
        c.tos = 0

    # ── Total Length — shown as info, not asked (auto-computed) ─────────────
    print("\n  Total Length — auto-computed at send time: IHL*4 + transport header + payload")

    # ── IP Identification ────────────────────────────────────────────────────
    if expert:
        c.ip_id = ask_int("IP Identification / ID (hex ok, 0x0000–0xFFFF)", 0, lo=0, hi=65535)
    else:
        c.ip_id = random.randint(0, 0xFFFF)
        print(f"  IP ID = 0x{c.ip_id:04X}  (random, Expert mode to set)")

    # ── IP Flags + Fragment Offset ───────────────────────────────────────────
    if expert:
        print("  IP Flags (3 bits):  bit2=Reserved(0)  bit1=DF(don't frag)  bit0=MF(more frags)")
        ip_flags = ask_int("IP Flags (0=none  2=DF)", 0, lo=0, hi=7)
        frag_off = ask_int("Fragment Offset   (units of 8B, normally 0)", 0, lo=0, hi=8191)
        c.ff = (ip_flags << 13) | frag_off
        print(f"    ↳ Flags+FragOff field = 0x{c.ff:04X}")
    else:
        c.ff = 0x0000

    # ── TTL ──────────────────────────────────────────────────────────────────
    c.ttl = ask_int("TTL (hops, 1–255)", 64, lo=1, hi=255)

    # ── Src / Dst IP ─────────────────────────────────────────────────────────
    c.src = ask_ip("Src IP", local_ip())
    c.dst = ask_ip("Dst IP", "192.168.1.1")

    # ── IP Options (must fit in opts_budget) ─────────────────────────────────
    c.opts = b''
    if expert and opts_budget > 0:
        if ask_yes(f"Add IP options?  (budget = {opts_budget}B / {opts_budget*2} hex chars)"):
            print(f"  Enter hex. Each option field padded to 4B. Max {opts_budget}B ({opts_budget*2} hex chars).")
            h = ask("  Options hex", "").replace(" ","").replace("0x","").upper()
            if h and all(ch in "0123456789ABCDEF" for ch in h):
                raw_len = len(h) // 2
                if raw_len > opts_budget:
                    print(f"    ↳ Too long ({raw_len}B > budget {opts_budget}B) → no options")
                else:
                    try:
                        c.opts = bytes.fromhex(h)
                        pad = (4 - len(c.opts) % 4) % 4
                        if pad: c.opts += b'\x00' * pad
                        if len(c.opts) > opts_budget:
                            c.opts = c.opts[:opts_budget]
                            print(f"    ↳ Truncated to budget: {c.opts.hex().upper()}")
                        else:
                            print(f"    ↳ {len(c.opts)}B IP options accepted: {c.opts.hex().upper()}")
                    except Exception as e:
                        print(f"    ↳ Error: {e} → no options")
            else:
                print("    ↳ Invalid hex → no options")
    elif expert and opts_budget == 0:
        print("  IP Options: none  (IHL=5 means zero options budget)")

    # ── IHL cross-check ──────────────────────────────────────────────────────
    derived_ihl = 5 + len(c.opts) // 4
    if expert and ihl_in != derived_ihl:
        print(f"\n  ⚠  IHL mismatch: you set IHL={ihl_in} ({ihl_in*4}B) "
              f"but options occupy {len(c.opts)}B → derived IHL={derived_ihl} ({derived_ihl*4}B)")
        print("     Using your IHL value (intentional malformed-packet craft).")
    c.ihl = ihl_in

    c.proto = proto
    c.SRC, c.DST = scapy.inet_aton(c.src), scapy.inet_aton(c.dst)
    c.custom_ck, c.ck_val = False, 0
    return c

def finalise_ip_cksum(c, transport_len, expert):
    tlen = c.ihl*4 + transport_len
    auto = calc_ip_checksum(c.version, c.ihl, c.tos, tlen, c.ip_id, c.ff,
                             c.ttl, c.proto, c.SRC, c.DST, c.opts)
    print("\n  ── IP Summary ─────────────────────────────────────────")
    print(f"  IHL={c.ihl} ({c.ihl*4}B hdr)  opts={len(c.opts)}B  Total Length={tlen}B (0x{tlen:04X})")
    print(f"  IP checksum (auto) = 0x{auto:04X}")
    if expert:
        raw = ask(f"  IP checksum override (Enter = keep auto 0x{auto:04X})", "auto").strip()
        if raw.lower() not in ("auto", ""):
            try:
                c.ck_val = int(raw.replace("0x",""),16) & 0xFFFF
                c.custom_ck = True
                print(f"    ↳ custom IP checksum 0x{c.ck_val:04X}"); return
            except: print("    ↳ Invalid → keeping auto")
    c.ck_val, c.custom_ck = auto, False

# ─────────────────────────────────────────────────────────────────────────────
# TCP options
# ─────────────────────────────────────────────────────────────────────────────

def ask_tcp_options(expert):
    if not expert: return b''
    if not ask_yes("Add TCP options?  (MSS, WScale, SACK, Timestamp …)"): return b''
    print("""  Common TCP options (hex):
    MSS 1460          → 02 04 05 B4
    NOP               → 01
    Window Scale ×128 → 03 03 07
    SACK Permitted    → 04 02
    Timestamp (zeros) → 08 0A 00 00 00 00 00 00 00 00""")
    h = ask("  Options hex (auto-padded to 4B)", "").replace(" ","").replace("0x","").upper()
    if h and all(ch in "0123456789ABCDEF" for ch in h):
        try:
            opts = bytes.fromhex(h)
            pad  = (4-len(opts)%4)%4
            if pad: opts += b'\x00'*pad
            print(f"    ↳ {len(opts)}B TCP options: {opts.hex().upper()}")
            return opts
        except Exception as e: print(f"    ↳ Error: {e} → no options")
    else: print("    ↳ Invalid → no options")
    return b''

# ─────────────────────────────────────────────────────────────────────────────
# Padding
# ─────────────────────────────────────────────────────────────────────────────

def ask_padding(expert):
    if not expert: return b''
    if not ask_yes("Add padding after payload?"): return b''
    cnt = ask_int("Padding byte count", 4, lo=1, hi=200)
    bv  = ask_int("Padding byte value (hex ok, e.g. 0x00)", 0, lo=0, hi=255)
    print(f"    ↳ {cnt}×0x{bv:02X}")
    return bytes([bv]) * cnt

# ─────────────────────────────────────────────────────────────────────────────
# Send params
# ─────────────────────────────────────────────────────────────────────────────

def ask_send_params():
    count    = ask_int("Number of packets to send", 1, lo=1)
    interval = float(ask("Interval between packets (seconds)", "1"))
    timeout  = float(ask("Reply timeout (seconds)", "2"))
    return count, interval, timeout

# ─────────────────────────────────────────────────────────────────────────────
# Three-way handshake
# ─────────────────────────────────────────────────────────────────────────────

def three_way_handshake(c, sport, dport, isn, window, tcp_opts,
                        piggyback, padding, timeout, lmac, rmac):
    """
    ─ SYN  →
    ←  SYN+ACK
    ─ ACK  →  (PSH+ACK if piggybacked data present)
    """
    data_off = 5 + len(tcp_opts)//4

    # ── 1/3 SYN ──────────────────────────────────────────────────────────────
    print(f"\n  ┌─ [1/3] SYN  {c.src}:{sport} → {c.dst}:{dport}  seq={isn}")
    syn_seg, syn_ck = build_tcp_segment(sport, dport, isn, 0, data_off, 0x02,
                                        window, 0, tcp_opts, b'', c.SRC, c.DST)
    syn_tlen = c.ihl*4 + len(syn_seg)
    syn_ipck = calc_ip_checksum(c.version, c.ihl, c.tos, syn_tlen, c.ip_id,
                                 c.ff, c.ttl, 6, c.SRC, c.DST, c.opts)
    syn_hdr  = build_ip_header(c.version, c.ihl, c.tos, syn_tlen, c.ip_id,
                                c.ff, c.ttl, 6, c.SRC, c.DST, c.opts, syn_ipck)
    ans, _ = sr_frame(syn_hdr + syn_seg, lmac, rmac, timeout)
    print(f"  │  SYN sent  TCPck=0x{syn_ck:04X}  IPck=0x{syn_ipck:04X}")

    # ── 2/3 parse SYN+ACK ────────────────────────────────────────────────────
    server_isn = None
    if ans:
        r = ans[0][1]
        if TCP in r:
            rt = r[TCP]
            rf = flags_str(int(rt.flags))
            print(f"  │  ← {r[IP].src}:{rt.sport}  flags={rf}  seq={rt.seq}  ack={rt.ack}")
            if int(rt.flags) & 0x12 == 0x12:
                server_isn = rt.seq
                print(f"  │  ✓ SYN+ACK  server_ISN={server_isn}")
            else:
                print(f"  │  ✗ Expected SYN+ACK, got {rf}")
        else: print("  │  ✗ Reply has no TCP layer")
    else: print("  │  ✗ No reply to SYN")
    print(f"  └─ [2/3] {'✓ SYN+ACK received' if server_isn is not None else '✗ No SYN+ACK — continuing anyway'}")

    # ── 3/3 ACK (+ optional piggybacked data) ────────────────────────────────
    my_seq  = (isn + 1) % (2**32)
    ack_num = ((server_isn + 1) % (2**32)) if server_isn is not None else 1
    ack_id  = (c.ip_id + 1) % 65536

    if piggyback:
        ack_flags = 0x18   # PSH+ACK — data rides on the acknowledgement
        label     = "PSH+ACK  (piggybacked data)"
    else:
        ack_flags = 0x10   # pure ACK
        label     = "ACK"

    print(f"\n  ┌─ [3/3] {label}")
    print(f"  │  seq={my_seq}  ack={ack_num}" + (f"  payload={len(piggyback)}B" if piggyback else ""))
    ack_seg, ack_ck = build_tcp_segment(sport, dport, my_seq, ack_num, data_off,
                                        ack_flags, window, 0, tcp_opts,
                                        piggyback + padding, c.SRC, c.DST)
    ack_tlen = c.ihl*4 + len(ack_seg)
    ack_ipck = calc_ip_checksum(c.version, c.ihl, c.tos, ack_tlen, ack_id,
                                 c.ff, c.ttl, 6, c.SRC, c.DST, c.opts)
    ack_hdr  = build_ip_header(c.version, c.ihl, c.tos, ack_tlen, ack_id,
                                c.ff, c.ttl, 6, c.SRC, c.DST, c.opts, ack_ipck)
    ans2, _ = sr_frame(ack_hdr + ack_seg, lmac, rmac, timeout)
    print(f"  │  {label} sent  TCPck=0x{ack_ck:04X}  IPck=0x{ack_ipck:04X}")

    if ans2:
        r2 = ans2[0][1]
        if TCP in r2:
            rt2 = r2[TCP]
            print(f"  │  ← flags={flags_str(int(rt2.flags))}  seq={rt2.seq}  ack={rt2.ack}")
            rdata = bytes(rt2.payload)
            if rdata: print(f"  │  ← server data {len(rdata)}B: {rdata[:64].hex()}")
        else: print("  │  ← Reply (no TCP layer)")
    else: print("  │  ← No reply")
    print("  └─ ✓ Three-way handshake complete\n")
    return my_seq, ack_num

# ─────────────────────────────────────────────────────────────────────────────
# TCP mode
# ─────────────────────────────────────────────────────────────────────────────

def mode_tcp(expert):
    c = ask_ip_fields(expert, proto=6)

    print("\n  ── TCP Fields ─────────────────────────────────────────")
    sport = ask_int("Src Port", random.randint(1024,65000), lo=0, hi=65535)
    dport = ask_int("Dst Port", 80, lo=0, hi=65535)

    flags_byte, flag_name = ask_tcp_flags()
    is_syn = (flags_byte == 0x02)

    seq   = ask_int("Seq number (ISN)", random.randint(1000, 0xFFFF0000) if is_syn else 0, lo=0)
    ack_n = ask_int("Ack number", 0, lo=0) if (not is_syn or expert) else 0

    window  = ask_int("Window size (bytes)", 65535, lo=0, hi=65535) if expert else 65535
    urg_ptr = ask_int("Urgent pointer", 0, lo=0, hi=65535) if (expert and flags_byte & 0x20) else 0
    tcp_opts = ask_tcp_options(expert)
    data_off = 5 + len(tcp_opts)//4

    # TCP checksum override — expert only
    tcp_custom_ck, tcp_ck_val = False, None
    if expert:
        raw_ck = ask("  TCP checksum override (hex, or Enter=auto)", "auto").strip()
        if raw_ck.lower() not in ("auto",""):
            try:
                tcp_ck_val    = int(raw_ck.replace("0x",""),16) & 0xFFFF
                tcp_custom_ck = True
                print(f"    ↳ custom TCP checksum 0x{tcp_ck_val:04X}")
            except: print("    ↳ Invalid → auto")

    # ── SYN → 3-way handshake ─────────────────────────────────────────────────
    if is_syn:
        print("\n  ► SYN selected → Three-Way Handshake")
        print("    SYN  ─►  ◄─ SYN+ACK  ─►  ACK (+ optional piggybacked payload)")
        print()
        print("    Piggybacking: sending data on the third ACK avoids an extra")
        print("    round-trip. The ACK flag is upgraded to PSH+ACK automatically.")
        piggyback = b''
        if ask_yes("Piggyback data on the final ACK?"):
            piggyback = ask_payload(default_len=32)
        padding = ask_padding(expert)
        count, interval, timeout = ask_send_params()
        lmac, rmac = resolve_mac(c.dst, c.src)
        for i in range(count):
            if i > 0: time.sleep(interval)
            if count > 1: print(f"\n  ── Handshake attempt {i+1}/{count} ──")
            c.ip_id = (c.ip_id + i*2) % 65536
            three_way_handshake(c, sport, dport, (seq+i)%(2**32), window,
                                tcp_opts, piggyback, padding, timeout, lmac, rmac)
        print("Done."); return

    # ── Non-SYN: direct send ──────────────────────────────────────────────────
    payload = b''
    if flags_byte & 0x08:    # PSH set
        print("\n  (PSH flag — payload expected)")
        payload = ask_payload()
    else:
        if ask_yes("Add payload to this segment?"):
            payload = ask_payload()
            if payload and flags_byte == 0x10:    # ACK-only + data → piggyback
                flags_byte |= 0x08
                flag_name = flags_str(flags_byte)
                print(f"    ↳ Piggybacking: flags upgraded to {flag_name} (PSH+ACK)")

    padding = ask_padding(expert)
    finalise_ip_cksum(c, data_off*4 + len(payload) + len(padding), expert)
    count, interval, timeout = ask_send_params()
    lmac, rmac = resolve_mac(c.dst, c.src)

    print(f"\n  Sending {count} TCP [{flag_name}] → {c.dst}:{dport}\n")
    for i in range(count):
        cur_seq = (seq + i * max(1,len(payload))) % (2**32)
        cur_ack = (ack_n + i) % (2**32)
        cur_id  = (c.ip_id + i) % 65536

        seg, tcp_ck = build_tcp_segment(
            sport, dport, cur_seq, cur_ack, data_off, flags_byte,
            window, urg_ptr, tcp_opts, payload + padding, c.SRC, c.DST,
            tcp_ck_val if tcp_custom_ck else None)

        tlen = c.ihl*4 + len(seg)
        ipck = c.ck_val if c.custom_ck else calc_ip_checksum(
            c.version, c.ihl, c.tos, tlen, cur_id, c.ff,
            c.ttl, 6, c.SRC, c.DST, c.opts)
        hdr = build_ip_header(c.version, c.ihl, c.tos, tlen, cur_id, c.ff,
                               c.ttl, 6, c.SRC, c.DST, c.opts, ipck)

        ans, _ = sr_frame(hdr + seg, lmac, rmac, timeout)
        print(f"  [{i+1}/{count}] {c.src}:{sport} → {c.dst}:{dport}  "
              f"{flag_name}  seq={cur_seq}  ack={cur_ack}  "
              f"pay={len(payload)}B  TCPck=0x{tcp_ck:04X}  IPck=0x{ipck:04X}")
        if ans:
            r = ans[0][1]
            if TCP in r:
                rt = r[TCP]
                print(f"    ← {r[IP].src}:{rt.sport}  flags={flags_str(int(rt.flags))}"
                      f"  seq={rt.seq}  ack={rt.ack}")
                rdata = bytes(rt.payload)
                if rdata: print(f"    ← data {len(rdata)}B: {rdata[:48].hex()}")
            else: print("    ← Reply (no TCP layer)")
        else: print("    ← No reply")
        if i < count-1: time.sleep(interval)
    print("\nDone.")

# ─────────────────────────────────────────────────────────────────────────────
# UDP mode
# ─────────────────────────────────────────────────────────────────────────────

def mode_udp(expert):
    c = ask_ip_fields(expert, proto=17)

    print("\n  ── UDP Fields ─────────────────────────────────────────")
    sport = ask_int("Src Port", random.randint(1024,65000), lo=0, hi=65535)
    dport = ask_int("Dst Port", 53, lo=0, hi=65535)

    udp_custom_ck, udp_ck_val = False, None
    if expert:
        print("  Checksum: 1=auto  2=disable(0x0000)  3=custom")
        ck_ch = ask("  Choice", "1")
        if ck_ch == "2":
            udp_ck_val, udp_custom_ck = 0x0000, True
            print("    ↳ Checksum disabled (0x0000)")
        elif ck_ch == "3":
            try:
                udp_ck_val    = int(ask("  Custom checksum (hex)","0x1234").replace("0x",""),16) & 0xFFFF
                udp_custom_ck = True
                print(f"    ↳ custom 0x{udp_ck_val:04X}")
            except: print("    ↳ Invalid → auto")

    payload = ask_payload(default_len=32)
    padding = ask_padding(expert)
    finalise_ip_cksum(c, 8 + len(payload) + len(padding), expert)
    count, interval, timeout = ask_send_params()
    lmac, rmac = resolve_mac(c.dst, c.src)

    print(f"\n  Sending {count} UDP → {c.dst}:{dport}\n")
    for i in range(count):
        cur_id = (c.ip_id + i) % 65536
        seg, udp_ck = build_udp_segment(sport, dport, payload+padding,
                                        c.SRC, c.DST,
                                        udp_ck_val if udp_custom_ck else None)
        tlen = c.ihl*4 + len(seg)
        ipck = c.ck_val if c.custom_ck else calc_ip_checksum(
            c.version, c.ihl, c.tos, tlen, cur_id, c.ff,
            c.ttl, 17, c.SRC, c.DST, c.opts)
        hdr = build_ip_header(c.version, c.ihl, c.tos, tlen, cur_id, c.ff,
                               c.ttl, 17, c.SRC, c.DST, c.opts, ipck)
        ans, _ = sr_frame(hdr + seg, lmac, rmac, timeout)
        print(f"  [{i+1}/{count}] {c.src}:{sport} → {c.dst}:{dport}  "
              f"pay={len(payload)}B  UDPck=0x{udp_ck:04X}  IPck=0x{ipck:04X}")
        if ans:
            r = ans[0][1]
            if UDP in r:
                ru = r[UDP]
                print(f"    ← {r[IP].src}:{ru.sport}  len={ru.len}")
                rdata = bytes(ru.payload)
                if rdata: print(f"    ← data {len(rdata)}B: {rdata[:48].hex()}")
            else: print("    ← Reply (no UDP layer)")
        else: print("    ← No reply")
        if i < count-1: time.sleep(interval)
    print("\nDone.")

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 58)
    print("         TCP / UDP  Raw Packet Crafter")
    print("  3-way handshake · Piggybacking · Checksum control")
    print("  TCP options · IP options · Padding · Multi-send")
    print("=" * 58)

    print("""
  ── Mode ──────────────────────────────────────────────
   Q) Quick   Src IP, Dst IP, ports, flags, payload only
              (all other fields use sensible defaults)

   E) Expert  + DSCP/ECN, IP-ID, IP flags, fragment offset
              + IP options, TCP options, window, urgent ptr
              + Checksum overrides, padding bytes
""")
    expert = ask("Mode", "Q").upper() == "E"
    print(f"  → {'Expert' if expert else 'Quick'} mode selected")

    print("""
  ── Protocol ──────────────────────────────────────────
   1) TCP   flags · 3-way handshake · piggybacking
   2) UDP   stateless · optional checksum disable
""")
    if ask("Protocol", "1") == "2":
        mode_udp(expert)
    else:
        mode_tcp(expert)

if __name__ == "__main__":
    try:    main()
    except KeyboardInterrupt: print("\nStopped.")
    except Exception as e:    print(f"Error: {e}"); raise
