# netlog

Traduce il traffico di rete in un log che capisce anche chi non è del mestiere.

```
22:20:00 [+] Dispositivo visto in rete: 192.168.1.50 (produttore Raspberry Pi Foundation, ...)
22:20:06 [!] dispositivo 192.168.1.10 comunica IN CHIARO con example.com: navigazione web non cifrata (HTTP).
22:20:08     dispositivo 192.168.1.10 <-> www.youtube.com: navigazione web cifrata (HTTPS) (inviati 130 B, ricevuti 2.9 kB)
```

## Installazione (Windows)

```
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

Per la cattura dal vivo serve [Npcap](https://npcap.com) e un terminale avviato come amministratore.

## Uso

```
.\.venv\Scripts\python netlog.py --list                # interfacce disponibili
.\.venv\Scripts\python netlog.py                       # cattura dal vivo
.\.venv\Scripts\python netlog.py --pcap file.pcap      # analizza una cattura salvata
.\.venv\Scripts\python netlog.py --json eventi.jsonl   # salva anche gli eventi in JSON Lines
.\.venv\Scripts\python netlog.py --ui                  # pagina web locale su http://127.0.0.1:8765
```

La pagina (`ui.html`) mostra gli avvisi, i programmi che usano la rete con le loro destinazioni e i dispositivi visti. È raggiungibile solo dal PC su cui gira netlog.

Senza Npcap si può provare con una cattura finta: `python make_sample.py`, poi `--pcap sample.pcap`.

## Limiti

- Vede solo il traffico del PC su cui gira, più broadcast e multicast della rete locale.
- Il contenuto cifrato resta cifrato: si leggono solo i metadati (nomi DNS, SNI, porte, volumi).
- Il servizio è dedotto dalla porta, quindi può sbagliare su porte non standard.

Usalo solo su reti tue o dove sei autorizzato.
