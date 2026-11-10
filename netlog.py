"""netlog - traduce il traffico di rete in un log leggibile da chi non e' del mestiere.

Uso:
    python netlog.py --list                 elenca le interfacce di rete
    python netlog.py                        cattura dal vivo (serve Npcap + amministratore)
    python netlog.py --iface "Wi-Fi"        cattura da un'interfaccia precisa
    python netlog.py --pcap file.pcap       analizza una cattura salvata (es. da Wireshark)
    python netlog.py --json eventi.jsonl    salva anche gli eventi in formato JSON Lines
    python netlog.py --ui                   mostra tutto in una pagina web locale
    python netlog.py --lang en              messaggi in inglese (default: lingua di Windows)

Pipeline:  pacchetto -> conversazione -> arricchimento (nome, processo, servizio) -> frase.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, AsyncSniffer, IPv6, Raw, conf, sniff

import messages
from messages import t

# Porta -> (chiave della descrizione in messages.py, e' in chiaro?)
SERVICES = {
    20: ("svc_ftp", True),
    21: ("svc_ftp", True),
    22: ("svc_ssh", False),
    23: ("svc_telnet", True),
    25: ("svc_smtp", True),
    43: ("svc_whois", False),
    53: ("svc_dns", False),
    67: ("svc_dhcp", False),
    68: ("svc_dhcp", False),
    80: ("svc_http", True),
    110: ("svc_pop3", True),
    123: ("svc_ntp", False),
    137: ("svc_netbios", False),
    138: ("svc_netbios", False),
    143: ("svc_imap", True),
    443: ("svc_https", False),
    445: ("svc_smb", False),
    465: ("svc_smtps", False),
    587: ("svc_submission", False),
    853: ("svc_dot", False),
    993: ("svc_imaps", False),
    995: ("svc_pop3s", False),
    1900: ("svc_ssdp", False),
    3389: ("svc_rdp", False),
    5353: ("svc_mdns", False),
    5355: ("svc_llmnr", False),
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
        self.paths: dict[str, str] = {}          # nome del programma -> percorso ("" se non leggibile)
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
                proc = psutil.Process(c.pid)
                name = self.table[(proto, c.laddr.port)] = proc.name()
            except psutil.Error:
                continue
            if not self.paths.get(name):
                try:
                    self.paths[name] = proc.exe()
                except (psutil.Error, OSError):
                    self.paths[name] = ""

    def listening(self) -> list[dict]:
        """Porte TCP su cui un programma di questo PC aspetta connessioni in arrivo."""
        try:
            conns = psutil.net_connections(kind="tcp")
        except (psutil.Error, OSError):
            return []
        ports = {}
        for c in conns:
            if c.status != psutil.CONN_LISTEN:
                continue
            try:
                name = psutil.Process(c.pid).name()
            except psutil.Error:
                name = t("unknown_program")
            # 127.0.0.1 e ::1 sono raggiungibili solo da questo PC; gli altri indirizzi dalla rete.
            exposed = not ipaddress.ip_address(c.laddr.ip).is_loopback
            entry = ports.setdefault((name, c.laddr.port), {
                "chi": name, "porta": c.laddr.port, "dalla_rete": False,
                "servizio": t(SERVICES[c.laddr.port][0]) if c.laddr.port in SERVICES else ""})
            entry["dalla_rete"] = entry["dalla_rete"] or exposed
        return sorted(ports.values(), key=lambda p: (not p["dalla_rete"], p["chi"].lower(), p["porta"]))

    def name(self, ip: str, proto: str, port: int) -> str | None:
        if ip not in self.own_ips:
            return None
        key = (proto, port)
        if key not in self.table and time.monotonic() - self.updated > 1.0:
            self.refresh()
        return self.table.get(key)


def cymru_owners(ips: list[str]) -> dict[str, str]:
    """Chiede a Team Cymru (whois.cymru.com) quale rete possiede ogni IP, in una sola richiesta."""
    request = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    with socket.create_connection(("whois.cymru.com", 43), timeout=10) as s:
        s.sendall(request.encode())
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    owners = {}
    for line in data.decode("utf-8", "replace").splitlines():
        # AS | IP | prefisso | paese | registro | data | nome della rete
        fields = [f.strip() for f in line.split("|")]
        if len(fields) == 7 and fields[0] != "NA":
            owners[fields[1]] = fields[6]
    return owners


PS_SIGNER = ("$input | ForEach-Object { $s = Get-AuthenticodeSignature -LiteralPath $_; "
             "\"$_|$($s.Status)|$($s.SignerCertificate.Subject)\" }")


class SignerLookup:
    """Percorso di un programma -> chi lo ha firmato ("" = nessuna firma valida).

    La firma digitale dice chi ha prodotto il file e che nessuno lo ha modificato.
    La verifica la fa Windows (PowerShell), in un thread a parte perche' e' lenta.
    """

    def __init__(self) -> None:
        self.signers: dict[str, str | None] = {}
        self.pending: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self.run, daemon=True).start()

    def get(self, path: str) -> str | None:
        if path not in self.signers:
            self.signers[path] = None
            self.pending.put(path)
        return self.signers[path]

    def run(self) -> None:
        while True:
            paths = [self.pending.get()]
            time.sleep(1)                      # raccoglie piu' percorsi in una sola verifica
            while not self.pending.empty():
                paths.append(self.pending.get())
            out = subprocess.run(["powershell", "-NoProfile", "-Command", PS_SIGNER],
                                 input="\n".join(paths), capture_output=True, text=True,
                                 errors="replace").stdout
            for line in out.splitlines():
                path, _, rest = line.partition("|")
                status, _, subject = rest.partition("|")
                if path in self.signers:
                    cn = re.search(r'CN=(?:"([^"]+)"|([^,]+))', subject)
                    self.signers[path] = (cn[1] or cn[2]) if status == "Valid" and cn else ""


class OwnerLookup:
    """IP pubblico -> chi lo gestisce (rete proprietaria + DNS inverso).

    Lavora in thread separati per non rallentare la cattura. Nota: gli IP contattati
    vengono inviati a Team Cymru e al proprio server DNS.
    """

    def __init__(self) -> None:
        self.labels: dict[str, str | None] = {}
        self.networks: dict[str, str] = {}       # IP -> solo il nome della rete proprietaria
        self.pending: queue.Queue[str] = queue.Queue()
        self.pool = ThreadPoolExecutor(max_workers=8)
        threading.Thread(target=self.run, daemon=True).start()

    def get(self, ip: str) -> str | None:
        if ip not in self.labels:
            self.labels[ip] = None
            self.pending.put(ip)
        return self.labels[ip]

    def run(self) -> None:
        while True:
            ips = [self.pending.get()]
            time.sleep(1)                      # raccoglie piu' indirizzi in una sola richiesta
            while not self.pending.empty():
                ips.append(self.pending.get())
            try:
                owners = cymru_owners(ips)
            except OSError:
                owners = {}
            for ip in ips:
                owner = owners.get(ip)
                if owner:
                    self.networks[ip] = owner
                    self.labels[ip] = t("net_server", owner=owner, ip=ip)
                self.pool.submit(self.reverse_dns, ip, owner)

    def reverse_dns(self, ip: str, owner: str | None) -> None:
        try:
            host = socket.gethostbyaddr(ip)[0]
        except OSError:
            return
        if not host.strip("."):                # alcuni server rispondono con un nome vuoto
            return
        self.labels[ip] = t("host_net", host=host, owner=owner) if owner else host


MEMORY_FILE = Path(__file__).with_name("netlog_memoria.json")


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
        self.owners = OwnerLookup() if live else None    # un pcap si analizza senza toccare la rete
        self.signers = SignerLookup() if live else None
        # Memoria tra un'esecuzione e l'altra (solo dal vivo): serve a riconoscere le novita'.
        # La prima volta non c'e' nulla con cui confrontare: si impara e basta.
        self.memory = None
        self.learning = not MEMORY_FILE.exists()
        self.dirty = False
        self.new_programs: set[str] = set()
        if live:
            self.memory = ({"programmi": {}, "dispositivi": []} if self.learning
                           else json.loads(MEMORY_FILE.read_text("utf-8")))
        self.json = open(json_path, "a", encoding="utf-8") if json_path else None
        self.now = time.time()

    # ---------- output ----------
    def emit(self, kind: str, text: str, **data) -> None:
        stamp = datetime.fromtimestamp(self.now).strftime("%H:%M:%S")
        mark = {"avviso": "[!]", "dispositivo": "[+]", "novita": "[*]"}.get(kind, "   ")
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
                      t("traffic", who=who, remote=remote, service=service,
                        up=human_bytes(up), down=human_bytes(down)),
                      chi=who, con=remote, servizio=service, inviati=up, ricevuti=down)

    def check_news(self) -> None:
        """Confronta cio' che si vede ora con la memoria delle esecuzioni precedenti."""
        with self.lock:
            seen = [(who, remote) for who, remote, _ in self.totals]
        known_programs = self.memory["programmi"]
        for who, remote in seen:
            path = self.procs.paths.get(who)
            if path is None:                       # non e' un programma di questo PC
                continue
            signer = self.signers.get(path) if path else None
            if path and signer is None:            # firma ancora in verifica: al prossimo giro
                continue
            if signer == "":
                self.alert_once(("firma", path), t("unsigned", who=who, path=path), chi=who)
            if who not in known_programs:
                known_programs[who] = []
                self.new_programs.add(who)
                self.dirty = True
                if not self.learning:
                    origin = t("signed_by", signer=signer) if signer else t("no_signature")
                    self.emit("novita", t("new_program", who=who, origin=origin,
                                          path=path or t("no_path")), chi=who)
            network = self.owners.networks.get(remote)
            if network and network not in known_programs[who]:
                known_programs[who].append(network)
                self.dirty = True
                # Per un programma nuovo ogni rete e' nuova: basta l'avviso sul programma.
                if not self.learning and who not in self.new_programs:
                    self.emit("novita", t("new_network", who=who, network=network),
                              chi=who, rete=network)
        if self.dirty:
            MEMORY_FILE.write_text(json.dumps(self.memory, ensure_ascii=False, indent=1), "utf-8")
            self.dirty = False

    def snapshot(self) -> dict:
        """Stato per la UI: per ogni programma, con chi ha parlato e quanto."""
        with self.lock:
            programs: dict[str, dict] = {}
            for (who, remote_ip, service), (up, down) in self.totals.items():
                if who not in programs:
                    path = self.procs.paths.get(who) if self.procs else None
                    programs[who] = {"chi": who, "percorso": path,
                                     "firma": self.signers.get(path) if path else None,
                                     "inviati": 0, "ricevuti": 0, "contatti": {}}
                p = programs[who]
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
            return {"lingua": messages.LANG,
                    "programmi": sorted(programs.values(),
                                        key=lambda p: -(p["inviati"] + p["ricevuti"])),
                    "in_ascolto": self.procs.listening() if self.procs else [],
                    "eventi": self.events[-200:]}

    # ---------- interpretazione ----------
    def describe_remote(self, ip: str) -> str:
        if ip in self.names:
            return self.names[ip]
        addr = ipaddress.ip_address(ip)
        if addr.is_multicast or ip.endswith(".255") or ip == "255.255.255.255":
            return t("whole_lan")
        if addr.is_private or addr.is_link_local:
            return t("local_device", ip=ip)
        owner = self.owners.get(ip) if self.owners and addr.is_global else None
        return owner or t("unknown_server", ip=ip)

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
        maker = t("maker", vendor=vendor) if vendor != mac else t("maker_unknown")
        detail = f"{ip} ({maker}, MAC {mac})"
        self.emit("dispositivo", t("device_seen", detail=detail), ip=ip, mac=mac, dettaglio=detail)
        if self.memory is not None and mac not in self.memory["dispositivi"]:
            self.memory["dispositivi"].append(mac)
            self.dirty = True
            if not self.learning:
                self.emit("novita", t("new_device", detail=detail), ip=ip, mac=mac)

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
                service, plaintext = "svc_icmp", False
            elif proto == "UDP" and rport == 443:
                service, plaintext = "svc_quic", False
            elif rport in SERVICES:
                service, plaintext = SERVICES[rport]
            elif lport in SERVICES:
                service, plaintext = SERVICES[lport]
            else:
                service, plaintext = "svc_unknown", False
            service = t(service, port=rport, proto=proto)

            who = (self.procs and self.procs.name(local, proto, lport)) or t("device", ip=local)
            remote_label = self.describe_remote(remote)

            counters = self.traffic[(who, remote_label, service)]
            counters[0 if outgoing else 1] += size
            self.totals[(who, remote, service)][0 if outgoing else 1] += size

            if plaintext and payload:
                self.alert_once(("chiaro", local, remote, rport),
                                t("plaintext", who=who, remote=remote_label, service=service),
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
    print(t("ui_ready", host=host), flush=True)


def main() -> int:
    # La lingua si legge per prima, cosi' anche l'aiuto (--help) esce in quella lingua.
    lang = argparse.ArgumentParser(add_help=False)
    lang.add_argument("--lang", choices=messages.LANGUAGES, default=messages.LANG)
    messages.LANG = lang.parse_known_args()[0].lang

    ap = argparse.ArgumentParser(description=t("cli_description"))
    ap.add_argument("--iface", help=t("cli_iface"))
    ap.add_argument("--pcap", help=t("cli_pcap"))
    ap.add_argument("--interval", type=float, default=10, help=t("cli_interval"))
    ap.add_argument("--json", help=t("cli_json"))
    ap.add_argument("--list", action="store_true", help=t("cli_list"))
    ap.add_argument("--ui", action="store_true", help=t("cli_ui"))
    ap.add_argument("--lang", choices=messages.LANGUAGES, help=t("cli_lang"))
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
        print(t("no_npcap"), file=sys.stderr)
        return 1

    sniffer = AsyncSniffer(iface=args.iface, prn=log.handle, store=False)
    sniffer.start()
    if args.ui:
        serve_ui(log)
    print(t("capturing", iface=args.iface or conf.iface), flush=True)
    if log.learning:
        print(t("first_run"), flush=True)
    try:
        while True:
            time.sleep(args.interval)
            log.now = time.time()
            log.report()
            log.check_news()
    except KeyboardInterrupt:
        sniffer.stop()
        log.report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
