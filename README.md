# payShield Command Sender

A lightweight desktop GUI for sending commands to a Thales payShield Hardware Security Module (HSM) over TCP, TLS, or UDP. Built with Python and Tkinter, it is aimed at developers, testers, and integration engineers who need to interact with a payShield without writing one-off scripts.

---

## Features

### Connectivity
- **TCP, TLS, and UDP** transport — switchable from the Options menu
- **Dual-target support** — run the same command set against a primary and secondary HSM simultaneously, useful for comparing responses across environments (e.g. dev vs. staging)
- **Persistent connection mode** — hold a single TCP/TLS socket open across all repeat sends to reduce handshake overhead
- **Connection check** — sends a `NC` (Node Check) command to the primary target and displays the firmware version returned

### Command Input
- **ASCII mode** — plain-text HSM command entry with multi-line support; inline binary payloads can be embedded using `<hex>` notation (e.g. `<0102DEAD>`)
- **Hex mode** — paste a raw hex string and send it verbatim
- Commands are framed automatically with the standard 2-byte big-endian length header and `HEAD` host header before transmission

### Load & Repeat Testing
- Configurable **connection count per target** — spawns one worker thread per connection for parallel sends
- Configurable **repeat sends per connection** — each worker loops independently
- Optional **random pre-send delay** (0 to N seconds) to simulate staggered real-world traffic
- Live **send counter** (`Sends: completed/total`) and **CPS meter** (commands per second, current and rolling average) that update in near real time

### TLS / mTLS
- Mutual TLS (mTLS) support via configurable CA certificate, client certificate, and client key
- Certificate fields accept file-browser selection or manual path entry
- TLS hostname verification is disabled to support HSMs addressed by IP

### Output & Logging
- **Colour-coded response log** — success responses, error response codes, connection events, and summaries each render in a distinct colour; Ctrl+click Run for random per-thread colours
- **Hex dump display** — each sent/received packet is shown as a formatted hex + ASCII dump
- **Hide responses** option — suppresses successful response lines to reduce noise during high-volume tests, showing only errors and summaries
- **Result log file** — optionally append every session's output to a `.txt` or `.log` file; each session begins with a structured header listing all active configuration and option values so the file is fully self-contained
- **Debug mode** — writes raw sent and received packet hex dumps to `debug_packets.log` for low-level troubleshooting
- **Copy log** — copies the entire visible log to the clipboard in one click
- **Log line limit** — caps the number of lines retained in the UI to keep memory usage bounded during long runs

### Configuration Persistence
All settings — hosts, ports, certificates, command text, protocol, options, and the result log path — are saved automatically to `payShield_Command_Sender_Config.json` on each run and restored on next launch. The host field maintains a history of the last 10 used addresses as a drop-down.

---

## Requirements

- Python 3.8 or later
- No third-party dependencies — standard library only (`tkinter`, `ssl`, `socket`, `threading`, `json`)

---

## Usage

```bash
python payShield_Command_Sender_3_1.py
```

1. Enter the **Primary Target** host and port.
2. Type a command in the ASCII field (e.g. `NC`) or switch to Hex mode.
3. Click **Run**. Use **Stop** to abort a run in progress.
4. Use **Check Pri Connection** to verify connectivity before running a full test.
5. Open **Options** to configure protocol, TLS, delays, and log behaviour.

### Inline binary payloads (ASCII mode)

Wrap any hex string in angle brackets to have it encoded as raw bytes within an ASCII command:

```
JK<0102ABCD>
```

This sends the ASCII characters `JKHEAD` followed by the decoded bytes `0x01 0x02 0xAB 0xCD`.

### Result log file format

When file logging is enabled, each session appends a block similar to:

```
========================================================================
  payShield Command Sender — Session Log
  Started : 2025-11-04 14:32:01
========================================================================

  TARGETS
------------------------------------------------------------------------
  Primary   : 192.168.0.31:2500
  Secondary : disabled

  NETWORK
------------------------------------------------------------------------
  Protocol            : TCP
  TLS                 : enabled
  Persistent conn     : yes (TCP only)
  CA Cert             : /certs/ca.pem
  ...

  SESSION RESULTS
------------------------------------------------------------------------
[T1-Pri] RECV (RTT: 0.003s):
4E 44 30 30 ...
...
========================================================================
```

---

## Configuration File

Settings are stored in `payShield_Command_Sender_Config.json` in the working directory. The file is created automatically on first run and can be edited manually or deleted to reset to defaults.

---

## Disclaimer

This tool is intended for use against HSMs you own or are authorised to test. It is provided without support.
