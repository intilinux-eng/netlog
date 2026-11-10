"""Tutte le frasi mostrate all'utente, in italiano e in inglese.

Ogni voce e' (italiano, inglese). Per aggiungere una frase: una riga qui, poi t("chiave") nel codice.
"""
from __future__ import annotations

import locale

LANGUAGES = ("it", "en")


def system_language() -> str:
    """Italiano se Windows e' in italiano, altrimenti inglese."""
    name = locale.getlocale()[0] or ""
    return "it" if name.lower().startswith("it") else "en"


LANG = system_language()

TEXT = {
    # --- servizi riconosciuti dalla porta ---
    "svc_ftp": ("trasferimento file FTP", "FTP file transfer"),
    "svc_ssh": ("accesso remoto sicuro (SSH)", "secure remote access (SSH)"),
    "svc_telnet": ("accesso remoto Telnet", "Telnet remote access"),
    "svc_smtp": ("invio posta (SMTP)", "sending mail (SMTP)"),
    "svc_whois": ("ricerca del proprietario di un indirizzo (WHOIS)", "address owner lookup (WHOIS)"),
    "svc_dns": ("ricerca indirizzi (DNS)", "address lookup (DNS)"),
    "svc_dhcp": ("assegnazione indirizzo di rete (DHCP)", "network address assignment (DHCP)"),
    "svc_http": ("navigazione web non cifrata (HTTP)", "unencrypted web browsing (HTTP)"),
    "svc_pop3": ("lettura posta (POP3)", "reading mail (POP3)"),
    "svc_ntp": ("sincronizzazione orologio (NTP)", "clock synchronization (NTP)"),
    "svc_netbios": ("nomi di rete Windows (NetBIOS)", "Windows network names (NetBIOS)"),
    "svc_imap": ("lettura posta (IMAP)", "reading mail (IMAP)"),
    "svc_https": ("navigazione web cifrata (HTTPS)", "encrypted web browsing (HTTPS)"),
    "svc_smb": ("condivisione file Windows (SMB)", "Windows file sharing (SMB)"),
    "svc_smtps": ("invio posta cifrato", "encrypted mail sending"),
    "svc_submission": ("invio posta", "sending mail"),
    "svc_dot": ("ricerca indirizzi cifrata (DNS su TLS)", "encrypted address lookup (DNS over TLS)"),
    "svc_imaps": ("lettura posta cifrata (IMAPS)", "encrypted mail reading (IMAPS)"),
    "svc_pop3s": ("lettura posta cifrata (POP3S)", "encrypted mail reading (POP3S)"),
    "svc_ssdp": ("ricerca dispositivi in casa (SSDP/UPnP)", "home device discovery (SSDP/UPnP)"),
    "svc_rdp": ("desktop remoto (RDP)", "remote desktop (RDP)"),
    "svc_mdns": ("annuncio dispositivi locali (mDNS)", "local device announcement (mDNS)"),
    "svc_llmnr": ("nomi di rete locale (LLMNR)", "local network names (LLMNR)"),
    "svc_icmp": ("diagnostica di rete (ping/ICMP)", "network diagnostics (ping/ICMP)"),
    "svc_quic": ("navigazione web cifrata (QUIC)", "encrypted web browsing (QUIC)"),
    "svc_unknown": ("servizio non riconosciuto (porta {port}/{proto})",
                    "unrecognized service (port {port}/{proto})"),

    # --- chi e con chi ---
    "device": ("dispositivo {ip}", "device {ip}"),
    "local_device": ("dispositivo locale {ip}", "local device {ip}"),
    "whole_lan": ("tutta la rete locale", "the whole local network"),
    "unknown_server": ("server sconosciuto {ip}", "unknown server {ip}"),
    "net_server": ("server della rete {owner} ({ip})", "server on the {owner} network ({ip})"),
    "host_net": ("{host} (rete {owner})", "{host} ({owner} network)"),
    "unknown_program": ("programma sconosciuto", "unknown program"),
    "maker": ("produttore {vendor}", "made by {vendor}"),
    "maker_unknown": ("produttore sconosciuto", "unknown maker"),

    # --- eventi ---
    "traffic": ("{who} <-> {remote}: {service} (inviati {up}, ricevuti {down})",
                "{who} <-> {remote}: {service} (sent {up}, received {down})"),
    "plaintext": ("{who} comunica IN CHIARO con {remote}: {service}. "
                  "Chiunque sulla rete puo' leggerne il contenuto.",
                  "{who} is talking UNENCRYPTED to {remote}: {service}. "
                  "Anyone on the network can read the content."),
    "unsigned": ("{who} usa la rete ma non ha una firma digitale valida: "
                 "non si puo' verificare chi lo ha prodotto ({path}).",
                 "{who} uses the network but has no valid digital signature: "
                 "there is no way to verify who made it ({path})."),
    "device_seen": ("Dispositivo visto in rete: {detail}", "Device seen on the network: {detail}"),
    "new_device": ("Dispositivo mai visto prima su questa rete: {detail}",
                   "Device never seen on this network before: {detail}"),
    "new_program": ("Programma mai visto prima in rete: {who} ({origin}, {path})",
                    "Program never seen on the network before: {who} ({origin}, {path})"),
    "new_network": ("{who} ha contattato per la prima volta la rete {network}",
                    "{who} contacted the {network} network for the first time"),
    "signed_by": ("firmato da {signer}", "signed by {signer}"),
    "no_signature": ("senza firma verificata", "signature not verified"),
    "no_path": ("percorso non leggibile", "path not readable"),

    # --- riga di comando ---
    "cli_description": ("Log di rete leggibile da esseri umani", "A network log humans can read"),
    "cli_iface": ("interfaccia da cui catturare (default: quella principale)",
                  "interface to capture from (default: the main one)"),
    "cli_pcap": ("analizza un file .pcap/.pcapng invece di catturare dal vivo",
                 "analyze a .pcap/.pcapng file instead of capturing live"),
    "cli_interval": ("secondi tra un riepilogo e l'altro", "seconds between summaries"),
    "cli_json": ("file JSON Lines su cui salvare gli eventi", "JSON Lines file to save events to"),
    "cli_list": ("elenca le interfacce ed esci", "list interfaces and exit"),
    "cli_ui": ("mostra tutto in una pagina web locale", "show everything in a local web page"),
    "cli_lang": ("lingua dei messaggi (default: quella di Windows)",
                 "language of the messages (default: the Windows one)"),
    "ui_ready": ("Pagina disponibile su http://{host}\n", "Page available at http://{host}\n"),
    "no_npcap": ("Npcap non trovato: installalo da https://npcap.com e riavvia il terminale "
                 "come amministratore. Nel frattempo puoi usare --pcap su un file salvato.",
                 "Npcap not found: install it from https://npcap.com and restart the terminal "
                 "as administrator. Meanwhile you can use --pcap on a saved file."),
    "capturing": ("In ascolto su {iface}. Ctrl+C per fermare.\n",
                  "Capturing on {iface}. Press Ctrl+C to stop.\n"),
    "first_run": ("Prima esecuzione: imparo cosa e' normale su questo PC. "
                  "Le novita' saranno segnalate dalle prossime volte.\n",
                  "First run: learning what is normal on this PC. "
                  "New things will be reported from the next runs.\n"),
}


def t(key: str, **values) -> str:
    """La frase `key` nella lingua corrente, con i valori inseriti."""
    return TEXT[key][LANGUAGES.index(LANG)].format(**values)
