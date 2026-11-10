# netlog

**Your network traffic, explained in plain sentences.** · [Italiano](README.it.md)

Wireshark shows packets. netlog shows what is happening: which program on your PC is talking to whom, whether it is encrypted, what is new since yesterday, and what is exposed to the network. It is built for people who are not network engineers, and as a hands-on way to learn system security on your own machine.

```
22:20:00 [+] Device seen on the network: 192.168.1.50 (made by Raspberry Pi Foundation, MAC b8:27:eb:11:22:33)
22:20:06 [!] device 192.168.1.10 is talking UNENCRYPTED to example.com: unencrypted web browsing (HTTP). Anyone on the network can read the content.
22:20:08     firefox.exe <-> www.youtube.com: encrypted web browsing (HTTPS) (sent 130 B, received 2.9 kB)
22:31:14 [*] Program never seen on the network before: updater.exe (signature not verified, C:\Users\me\AppData\Local\Temp\updater.exe)
```

## Why

On its first real run, netlog surfaced a program nobody remembered installing: a residential-proxy agent, bundled with another installer, that was relaying third-party traffic through the home connection and restarting at every logon. It was holding connections to about twenty hosting servers on an unusual port. That is the kind of thing this tool exists to make visible.

## What it does

- **Who is using the network.** Traffic is grouped by program (`firefox.exe`, `Code.exe`), not by IP and port.
- **Names instead of addresses.** Destinations are named from DNS answers, the TLS server name, the owning network (for example "Hetzner") and reverse DNS.
- **Program identity.** Each program shows its file path and who digitally signed it. A program using the network without a valid signature raises an alert.
- **What is new.** netlog remembers programs, the networks each one contacts, and devices on the LAN. From the second run on, it reports anything never seen before.
- **What is exposed.** Lists the programs accepting incoming connections and highlights the ones reachable from other devices.
- **Unencrypted traffic.** Flags protocols that travel in clear text (HTTP, Telnet, FTP, …).
- **Local web page.** A simple page with sentences, not tables of packets. Reachable only from the PC running netlog.
- **Italian and English.** Console, page and help follow the Windows language; `--lang` overrides it.

## Install (Windows)

Requires Python 3.10+ and [Npcap](https://npcap.com) for live capture.

```
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

## Use

```
.\.venv\Scripts\python netlog.py --ui                  # live capture + page on http://127.0.0.1:8765
.\.venv\Scripts\python netlog.py                       # live capture, console only
.\.venv\Scripts\python netlog.py --pcap file.pcap      # analyze a capture saved by Wireshark
.\.venv\Scripts\python netlog.py --json events.jsonl   # also save events as JSON Lines
.\.venv\Scripts\python netlog.py --lang it             # force Italian (or en)
.\.venv\Scripts\python netlog.py --list                # list network interfaces
```

No Npcap? Try it on a synthetic capture: `python make_sample.py`, then `--pcap sample.pcap`.

The first live run only learns what is normal on your PC and writes it to `netlog_memoria.json`. Novelty reports start with the second run.

## How it works

```
packet → local/remote side → enrichment → sentence
```

1. **Capture** with Scapy on top of Npcap, or read a `.pcap` file.
2. **Sides.** Decide which end is "ours" and which program owns the local port (psutil).
3. **Enrichment.** Service from the port; destination name from DNS, TLS SNI, HTTP Host, network owner and reverse DNS; program path and Authenticode signer.
4. **Sentence.** Every user-facing string lives in [messages.py](messages.py), in both languages.

Everything is in [netlog.py](netlog.py), a single file meant to be read.

## Privacy and limits

- netlog never decrypts anything. For encrypted traffic it reads only metadata: names, ports, volumes.
- In live mode, the public IPs you contact are sent to Team Cymru (`whois.cymru.com`, unencrypted) and to your DNS server, to find out who owns them. Analyzing a `.pcap` makes no network requests.
- It sees the traffic of the PC it runs on, plus broadcast and multicast from the local network. It does not see other devices' conversations.
- The service is guessed from the port, so non-standard ports can be mislabeled, and "unencrypted" alerts can be wrong for protocols that encrypt on top of port 80.
- Very short connections may not be matched to a program and appear as "device <your IP>".
- `netlog_memoria.json` and `.jsonl` logs describe your machine and network. They are git-ignored: do not publish them.
- Windows only for now (signature check and process lookup).

**Use it only on networks you own or are authorized to monitor.**

## License

[MIT](LICENSE)
