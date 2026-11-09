"""Genera sample.pcap: una cattura finta per provare netlog.py senza Npcap."""
from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

PC, ROUTER, TV = "192.168.1.10", "192.168.1.1", "192.168.1.50"
SITE, OLD = "142.250.180.14", "93.184.216.34"


def client_hello(host: str) -> bytes:
    name = host.encode()
    sni = b"\x00" + len(name).to_bytes(2, "big") + name
    sni = len(sni).to_bytes(2, "big") + sni
    ext = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


pkts = [
    Ether() / ARP(op=1, hwsrc="b8:27:eb:11:22:33", psrc=TV, pdst=ROUTER),
    Ether() / IP(src=PC, dst=ROUTER) / UDP(sport=50000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="www.youtube.com")),
    Ether() / IP(src=ROUTER, dst=PC) / UDP(sport=53, dport=50000)
    / DNS(qr=1, qd=DNSQR(qname="www.youtube.com"),
          an=DNSRR(rrname="www.youtube.com", rdata=SITE)),
    Ether() / IP(src=PC, dst=SITE) / TCP(sport=50001, dport=443, flags="PA")
    / Raw(client_hello("www.youtube.com")),
    Ether() / IP(src=SITE, dst=PC) / TCP(sport=443, dport=50001, flags="PA") / Raw(bytes(1400)),
    Ether() / IP(src=SITE, dst=PC) / TCP(sport=443, dport=50001, flags="PA") / Raw(bytes(1400)),
    Ether() / IP(src=PC, dst=OLD) / TCP(sport=50002, dport=80, flags="PA")
    / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    Ether() / IP(src=TV, dst="239.255.255.250") / UDP(sport=40000, dport=1900)
    / Raw(b"M-SEARCH * HTTP/1.1\r\n\r\n"),
    Ether() / IP(src=PC, dst="8.8.4.4") / TCP(sport=50003, dport=23, flags="PA") / Raw(b"login: admin\r\n"),
]
for i, p in enumerate(pkts):
    p.time = 1_794_000_000 + i
wrpcap("sample.pcap", pkts)
print(f"sample.pcap scritto ({len(pkts)} pacchetti)")
