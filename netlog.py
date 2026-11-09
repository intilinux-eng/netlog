"""netlog - traduce il traffico di rete in un log leggibile da chi non e' del mestiere.

Uso:
    python netlog.py --list                 elenca le interfacce di rete
    python netlog.py                        cattura dal vivo (serve Npcap + amministratore)
    python netlog.py --iface "Wi-Fi"        cattura da un'interfaccia precisa
    python netlog.py --pcap file.pcap       analizza una cattura salvata (es. da Wireshark)
    python netlog.py --json eventi.jsonl    salva anche gli eventi in formato JSON Lines
    python netlog.py --ui                   mostra tutto in una pagina web locale

Pipeline:  pacchetto -> conversazione -> arricchimento (nome, processo, servizio) -> frase.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, AsyncSniffer, IPv6, Raw, conf, sniff

# Porta -> (descrizione per umani, e' in chiaro?)
SERVICES = {
    20: ("trasferimento file FTP", True),
    21: ("trasferimento file FTP", True),
    22: ("accesso remoto sicuro (SSH)", False),
    23: ("accesso remoto Telnet", True),
    25: ("invio posta (SMTP)", True),
    53: ("ricerca indirizzi (DNS)", False),
    67: ("assegnazione indirizzo di rete (DHCP)", False),
    68: ("assegnazione indirizzo di rete (DHCP)", False),
    80: ("navigazione web non cifrata (HTTP)", True),
    110: ("lettura posta (POP3)", True),
    123: ("sincronizzazione orologio (NTP)", False),
    137: ("nomi di rete Windows (NetBIOS)", False),
    138: ("nomi di rete Windows (NetBIOS)", False),
    143: ("lettura posta (IMAP)", True),
    443: ("navigazione web cifrata (HTTPS)", False),
    445: ("condivisione file Windows (SMB)", False),
    465: ("invio posta cifrato", False),
    587: ("invio posta", False),
    853: ("ricerca indirizzi cifrata (DNS su TLS)", False),
    993: ("lettura posta cifrata (IMAPS)", False),
    995: ("lettura posta cifrata (POP3S)", False),
    1900: ("ricerca dispositivi in casa (SSDP/UPnP)", False),
    3389: ("desktop remoto (RDP)", False),
    5353: ("annuncio dispositivi locali (mDNS)", False),
    5355: ("nomi di rete locale (LLMNR)", False),
}


def human_bytes(n: int) -> str:
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n} B"


def tls_sni(data: bytes) -> str | None:
    """Estrae il nome del sito (SNI) da un TLS ClientHello: viaggia in chiaro."""
    try:
        if len(data) < 44 or data[0] != 0x16 or data[5] != 0x01:
            return None
        p = 5 + 4 + 2 + 32                               # record, handshake, versione, random
        p += 1 + data[p]                                 # session id
        p += 2 + int.from_bytes(data[p:p + 2], "big")    # cipher suites
        p += 1 + data[p]                                 # compressione
        end = min(len(data), p + 2 + int.from_bytes(data[p:p + 2], "big"))
        p += 2
        while p + 4 <= end:
            ext_type = int.from_bytes(data[p:p + 2], "big")
            ext_len = int.from_bytes(data[p + 2:p + 4], "big")
            p += 4
            if ext_type == 0:                            # server_name
                n = int.from_bytes(data[p + 3:p + 5], "big")
                name = data[p + 5:p + 5 + n].decode("ascii", "replace")
                return name or None
            p += ext_len
    except IndexError:
        pass
    return None


def http_host(data: bytes) -> str | None:
    if not data.split(b" ", 1)[0] in (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS"):
        return None
    for line in data.split(b"\r\n")[1:]:
        if line.lower().startswith(b"host:"):
            return line[5:].strip().decode("ascii", "replace")
    return None


class ProcessLookup:
    """Porta locale -> nome del programma che la sta usando (solo cattura dal vivo)."""

    def __init__(self) -> None:
        self.table: dict[tuple[str, int], str] = {}
        self.updated = 0.0
        self.own_ips = {a.address.split("%")[0]
                        for addrs in psutil.net_if_addrs().values() for a in addrs}

    def refresh(self) -> None:
        self.updated = time.monotonic()
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.Error, OSError):
            return
        for c in conns:
            if not c.laddr or not c.pid:
                continue
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            try:
                self.table[(proto, c.laddr.port)] = psutil.Process(c.pid).name()
            except psutil.Error:
                pass

    def name(self, ip: str, proto: str, port: int) -> str | None:
        if ip not in self.own_ips:
            return None
        key = (proto, port)
        if key not in self.table and time.monotonic() - self.updated > 1.0:
            self.refresh()
        return self.table.get(key)


class NetLog:
    def __init__(self, live: bool, json_path: str | None) -> None:
        self.lock = threading.Lock()
        self.names: dict[str, str] = {}          # IP remoto -> nome (da DNS, SNI, Host)
        self.devices: dict[str, str] = {}        # MAC -> IP dei dispositivi visti
        self.alerted: set[tuple] = set()
        # (chi, con chi, servizio) -> [byte inviati, byte ricevuti]
        self.traffic: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
        # Per la UI: totali dall'avvio per (chi, IP remoto, servizio) e storico avvisi/dispositivi
        self.totals: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
        self.events: list[dict] = []
        self.procs = ProcessLookup() if live else None
        self.json = open(json_path, "a", encoding="utf-8") if json_path else None
        self.now = time.time()

    # ---------- output ----------
    def emit(self, kind: str, text: str, **data) -> None:
        stamp = datetime.fromtimestamp(self.now).strftime("%H:%M:%S")
        mark = {"avviso": "[!]", "dispositivo": "[+]"}.get(kind, "   ")
        print(f"{stamp} {mark} {text}", flush=True)
        record = {"ora": datetime.fromtimestamp(self.now).isoformat(timespec="seconds"),
                  "tipo": kind, "testo": text, **data}
        if kind != "traffico":
            self.events.append(record)
        if self.json:
            self.json.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.json.flush()

    def alert_once(self, key: tuple, text: str, **data) -> None:
        if key not in self.alerted:
            self.alerted.add(key)
            self.emit("avviso", text, **data)

    def report(self) -> None:
        with self.lock:
            rows = sorted(self.traffic.items(), key=lambda kv: -sum(kv[1]))
            self.traffic.clear()
        for (who, remote, service), (up, down) in rows:
            self.emit("traffico",
                      f"{who} <-> {remote}: {service} "
                      f"(inviati {human_bytes(up)}, ricevuti {human_bytes(down)})",
                      chi=who, con=remote, servizio=service, inviati=up, ricevuti=down)

    def snapshot(self) -> dict:
        """Stato per la UI: per ogni programma, con chi ha parlato e quanto."""
        with self.lock:
            programs: dict[str, dict] = {}
            for (who, remote_ip, service), (up, down) in self.totals.items():
                p = programs.setdefault(who, {"chi": who, "inviati": 0, "ricevuti": 0, "contatti": {}})
                p["inviati"] += up
                p["ricevuti"] += down
                # I nomi si imparano strada facendo: si risolvono qui, cosi' IP diversi
                # dello stesso sito finiscono nella stessa riga.
                c = p["contatti"].setdefault((self.describe_remote(remote_ip), service), [0, 0])
                c[0] += up
                c[1] += down
            for p in programs.values():
                p["contatti"] = sorted(
                    ({"con": con, "servizio": srv, "inviati": u, "ricevuti": d}
                     for (con, srv), (u, d) in p["contatti"].items()),
                    key=lambda c: -(c["inviati"] + c["ricevuti"]))
            return {"programmi": sorted(programs.values(),
                                        key=lambda p: -(p["inviati"] + p["ricevuti"])),
                    "eventi": self.events[-200:]}

    # ---------- interpretazione ----------
    def describe_remote(self, ip: str) -> str:
        if ip in self.names:
            return self.names[ip]
        addr = ipaddress.ip_address(ip)
        if addr.is_multicast or ip.endswith(".255") or ip == "255.255.255.255":
            return "tutta la rete locale"
        if addr.is_private or addr.is_link_local:
            return f"dispositivo locale {ip}"
        return f"server sconosciuto {ip}"

    def learn_dns(self, dns) -> None:
        if not dns.qr or not dns.ancount:
            return
        try:
            question = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
            qname = question.qname.decode("ascii", "replace").rstrip(".")
            for i in range(dns.ancount):
                rr = dns.an[i]
                if rr.type in (1, 28):               # A, AAAA
                    self.names.setdefault(str(rr.rdata), qname)
        except (AttributeError, IndexError, TypeError):
            pass

    def handle_arp(self, pkt) -> None:
        mac, ip = pkt[ARP].hwsrc, pkt[ARP].psrc
        if ip == "0.0.0.0" or mac in self.devices:
            return
        self.devices[mac] = ip
        try:
            vendor = conf.manufdb._get_manuf(mac)
        except Exception:
            vendor = mac
        maker = f"produttore {vendor}" if vendor != mac else "produttore sconosciuto"
        self.emit("dispositivo", f"Dispositivo visto in rete: {ip} ({maker}, MAC {mac})",
                  ip=ip, mac=mac)

    def handle(self, pkt) -> None:
        with self.lock:
            self.now = float(pkt.time)
            if ARP in pkt:
                self.handle_arp(pkt)
                return
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                return
            src, dst, size = ip.src, ip.dst, len(pkt)

            if TCP in pkt or UDP in pkt:
                proto = "TCP" if TCP in pkt else "UDP"
                l4 = pkt[proto]
                sport, dport = l4.sport, l4.dport
            elif ICMP in pkt:
                proto, sport, dport = "ICMP", 0, 0
            else:
                return

            if DNS in pkt:
                self.learn_dns(pkt[DNS])

            # Chi e' il lato "nostro"? Quello con indirizzo privato; in dubbio, chi ha la porta alta.
            src_local = ipaddress.ip_address(src).is_private
            dst_local = ipaddress.ip_address(dst).is_private
            outgoing = src_local and not dst_local or (src_local == dst_local and sport >= dport)
            local, lport, remote, rport = (src, sport, dst, dport) if outgoing else (dst, dport, src, sport)

            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            if outgoing and payload and proto == "TCP":
                name = tls_sni(payload) or http_host(payload)
                if name:
                    self.names[remote] = name

            if proto == "ICMP":
                service, plaintext = "diagnostica di rete (ping/ICMP)", False
            elif rport in SERVICES:
                service, plaintext = SERVICES[rport]
            elif lport in SERVICES:
                service, plaintext = SERVICES[lport]
            elif proto == "UDP" and rport == 443:
                service, plaintext = "navigazione web cifrata (QUIC)", False
            else:
                service, plaintext = f"servizio non riconosciuto (porta {rport}/{proto})", False
            if proto == "UDP" and rport == 443:
                service = "navigazione web cifrata (QUIC)"

            who = (self.procs and self.procs.name(local, proto, lport)) or f"dispositivo {local}"
            remote_label = self.describe_remote(remote)

            counters = self.traffic[(who, remote_label, service)]
            counters[0 if outgoing else 1] += size
            self.totals[(who, remote, service)][0 if outgoing else 1] += size

            if plaintext and payload:
                self.alert_once(("chiaro", local, remote, rport),
                                f"{who} comunica IN CHIARO con {remote_label}: {service}. "
                                f"Chiunque sulla rete puo' leggerne il contenuto.",
                                chi=who, con=remote_label, servizio=service)


UI_PORT = 8765


def serve_ui(log: NetLog) -> None:
    """Pagina web locale: raggiungibile solo da questo PC (127.0.0.1)."""
    page = Path(__file__).with_name("ui.html").read_bytes()
    host = f"127.0.0.1:{UI_PORT}"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            # Rifiuta richieste arrivate con un altro nome host (DNS rebinding da siti web).
            if self.headers.get("Host") != host:
                self.send_error(403)
                return
            if self.path == "/":
                body, ctype = page, "text/html; charset=utf-8"
            elif self.path == "/api/state":
                body = json.dumps(log.snapshot(), ensure_ascii=False).encode()
                ctype = "application/json; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    class Server(ThreadingHTTPServer):
        # Su Windows il riuso dell'indirizzo lascerebbe aprire la stessa porta a un altro processo.
        allow_reuse_address = False

    server = Server(("127.0.0.1", UI_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Pagina disponibile su http://{host}\n", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Log di rete leggibile da esseri umani")
    ap.add_argument("--iface", help="interfaccia da cui catturare (default: quella principale)")
    ap.add_argument("--pcap", help="analizza un file .pcap/.pcapng invece di catturare dal vivo")
    ap.add_argument("--interval", type=float, default=10, help="secondi tra un riepilogo e l'altro")
    ap.add_argument("--json", help="file JSON Lines su cui salvare gli eventi")
    ap.add_argument("--list", action="store_true", help="elenca le interfacce ed esci")
    ap.add_argument("--ui", action="store_true", help="mostra tutto in una pagina web locale")
    args = ap.parse_args()

    if args.list:
        conf.ifaces.show()
        return 0

    log = NetLog(live=not args.pcap, json_path=args.json)

    if args.pcap:
        sniff(offline=args.pcap, prn=log.handle, store=False)
        log.report()
        if args.ui:
            serve_ui(log)
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        return 0

    if not conf.use_pcap:
        print("Npcap non trovato: installalo da https://npcap.com e riavvia il terminale "
              "come amministratore. Nel frattempo puoi usare --pcap su un file salvato.",
              file=sys.stderr)
        return 1

    sniffer = AsyncSniffer(iface=args.iface, prn=log.handle, store=False)
    sniffer.start()
    if args.ui:
        serve_ui(log)
    print(f"In ascolto su {args.iface or conf.iface}. Ctrl+C per fermare.\n", flush=True)
    try:
        while True:
            time.sleep(args.interval)
            log.now = time.time()
            log.report()
    except KeyboardInterrupt:
        sniffer.stop()
        log.report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
