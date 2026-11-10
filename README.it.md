# netlog

**Il traffico della tua rete, spiegato in frasi.** · [English](README.md)

Wireshark mostra pacchetti. netlog mostra cosa sta succedendo: quale programma del tuo PC parla con chi, se è cifrato, cosa c'è di nuovo rispetto a ieri e cosa è esposto alla rete. È pensato per chi non è del mestiere, e come modo pratico per imparare la sicurezza di sistema sul proprio computer.

```
22:20:00 [+] Dispositivo visto in rete: 192.168.1.50 (produttore Raspberry Pi Foundation, MAC b8:27:eb:11:22:33)
22:20:06 [!] dispositivo 192.168.1.10 comunica IN CHIARO con example.com: navigazione web non cifrata (HTTP). Chiunque sulla rete puo' leggerne il contenuto.
22:20:08     firefox.exe <-> www.youtube.com: navigazione web cifrata (HTTPS) (inviati 130 B, ricevuti 2.9 kB)
22:31:14 [*] Programma mai visto prima in rete: updater.exe (senza firma verificata, C:\Users\me\AppData\Local\Temp\updater.exe)
```

## Perché

Alla prima esecuzione reale, netlog ha fatto emergere un programma che nessuno ricordava di aver installato: un agente di proxy residenziale, arrivato insieme a un altro installer, che faceva passare traffico di terzi dalla connessione di casa e ripartiva a ogni accesso. Teneva connessioni aperte verso una ventina di server di hosting su una porta insolita. Lo strumento esiste per rendere visibili cose così.

## Cosa fa

- **Chi usa la rete.** Il traffico è raggruppato per programma (`firefox.exe`, `Code.exe`), non per IP e porta.
- **Nomi al posto degli indirizzi.** Le destinazioni prendono il nome dalle risposte DNS, dal nome del server TLS, dalla rete proprietaria (ad esempio "Hetzner") e dal DNS inverso.
- **Identità del programma.** Ogni programma mostra il percorso del file e chi lo ha firmato digitalmente. Un programma che usa la rete senza firma valida genera un avviso.
- **Novità.** netlog ricorda i programmi, le reti che ciascuno contatta e i dispositivi sulla rete locale. Dalla seconda esecuzione segnala tutto ciò che non aveva mai visto.
- **Cosa è esposto.** Elenca i programmi che accettano connessioni in arrivo ed evidenzia quelli raggiungibili dagli altri dispositivi.
- **Traffico in chiaro.** Segnala i protocolli che viaggiano senza cifratura (HTTP, Telnet, FTP, …).
- **Pagina web locale.** Una pagina semplice, fatta di frasi e non di tabelle di pacchetti. È raggiungibile solo dal PC su cui gira netlog.
- **Italiano e inglese.** Console, pagina e aiuto seguono la lingua di Windows; `--lang` la cambia.

## Installazione (Windows)

Servono Python 3.10+ e [Npcap](https://npcap.com) per la cattura dal vivo.

```
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

## Uso

```
.\.venv\Scripts\python netlog.py --ui                  # cattura dal vivo + pagina su http://127.0.0.1:8765
.\.venv\Scripts\python netlog.py                       # cattura dal vivo, solo console
.\.venv\Scripts\python netlog.py --pcap file.pcap      # analizza una cattura salvata da Wireshark
.\.venv\Scripts\python netlog.py --json eventi.jsonl   # salva anche gli eventi in JSON Lines
.\.venv\Scripts\python netlog.py --lang en             # forza l'inglese (o it)
.\.venv\Scripts\python netlog.py --list                # elenca le interfacce di rete
```

Senza Npcap si può provare su una cattura finta: `python make_sample.py`, poi `--pcap sample.pcap`.

La prima esecuzione dal vivo impara soltanto cosa è normale sul tuo PC e lo scrive in `netlog_memoria.json`. Le novità vengono segnalate dalla seconda esecuzione.

## Come funziona

```
pacchetto → lato locale/remoto → arricchimento → frase
```

1. **Cattura** con Scapy sopra Npcap, oppure lettura di un file `.pcap`.
2. **Lati.** Si decide quale estremo è il "nostro" e quale programma possiede la porta locale (psutil).
3. **Arricchimento.** Servizio dedotto dalla porta; nome della destinazione da DNS, SNI di TLS, Host di HTTP, rete proprietaria e DNS inverso; percorso del programma e firmatario Authenticode.
4. **Frase.** Ogni testo mostrato all'utente sta in [messages.py](messages.py), nelle due lingue.

Tutto il resto è in [netlog.py](netlog.py), un solo file pensato per essere letto.

## Privacy e limiti

- netlog non decifra mai nulla. Del traffico cifrato legge solo i metadati: nomi, porte, volumi.
- Nella cattura dal vivo, gli IP pubblici che contatti vengono inviati a Team Cymru (`whois.cymru.com`, in chiaro) e al tuo server DNS, per sapere a chi appartengono. L'analisi di un `.pcap` non fa richieste in rete.
- Vede il traffico del PC su cui gira, più broadcast e multicast della rete locale. Non vede le conversazioni degli altri dispositivi.
- Il servizio è dedotto dalla porta: su porte non standard può sbagliare, e l'avviso "in chiaro" può essere errato per protocolli che cifrano sopra la porta 80.
- Le connessioni molto brevi possono non essere associate a un programma e comparire come "dispositivo <il tuo IP>".
- `netlog_memoria.json` e i log `.jsonl` descrivono il tuo computer e la tua rete. Sono esclusi da git: non pubblicarli.
- Per ora solo Windows (verifica della firma e associazione ai processi).

**Usalo solo su reti tue o che sei autorizzato a monitorare.**

## Licenza

[MIT](LICENSE)
