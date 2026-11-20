# OhBoyScan CLI

OhBoyScan is a small command-line tool that **checks whether a MikroTik router has been
changed without permission**. It runs on a separate device, such as a Raspberry Pi 3B+ or a
Linux laptop, connected to the router by cable.

The tool works in three steps:

1. You save a **trusted copy** of the router configuration and sign it with your
   **ECDSA key** (NIST P-256 curve + SHA-256).
2. From time to time, the tool reads the router configuration again and compares it with
   the trusted copy.
3. If something changed (a service was enabled, a firewall rule was edited, a script was
   modified) or if someone edited the trusted copy itself, the tool **raises an alert**.

This tool is the implementation of the paper *"Hardware-Based Network Auditing and
Signature Validation Using ECDSA"*. If you use it in academic work, please cite it
(see [How to cite](#14-how-to-cite)).

> The tool's messages and reports are in Portuguese. The commands and options are in English.

---

## Contents

1. [How it works](#1-how-it-works)
2. [Do I need to build it?](#2-do-i-need-to-build-it)
3. [Building](#3-building)
4. [Preparing the MikroTik router](#4-preparing-the-mikrotik-router)
5. [Configuring the tool](#5-configuring-the-tool)
6. [Saving the router configuration (the baseline)](#6-saving-the-router-configuration-the-baseline)
7. [Running the audit](#7-running-the-audit)
8. [Running the audit automatically](#8-running-the-audit-automatically)
9. [Test results on a real router](#9-test-results-on-a-real-router)
10. [Testing without a router](#10-testing-without-a-router)
11. [Security notes](#11-security-notes)
12. [Command reference](#12-command-reference)
13. [Project files](#13-project-files)
14. [How to cite](#14-how-to-cite)

---

## 1. How it works

```
   Auditor (Raspberry Pi or laptop)                              MikroTik router
 ┌─────────────────────────────────────────┐                 ┌───────────────────────┐
 │ ohboyscan                               │   RouterOS API  │ /ip/service           │
 │                                         │   over TLS      │ /ip/firewall/filter   │
 │  init         -> creates your key pair  │   (port 8729)   │ /user                 │
 │  preset save  -> reads router, signs    │ ◄─────────────► │ /system/script        │
 │  audit        -> reads router, compares │   read-only     │                       │
 │                                         │   user          │                       │
 └─────────────────────────────────────────┘                 └───────────────────────┘
```

### The three commands

| Step | Command | When you run it | Needs your passphrase? |
|---|---|---|---|
| 1 | `init` | Once, for each person (operator) | Yes, you choose it here |
| 2 | `preset save` | When the router is in a **known good state**, and again after every **approved** change | Yes |
| 3 | `audit` | Any time, usually automatically every few minutes | **No** |

The audit **only needs the public key**. This means it can run unattended (from cron or
systemd) and the private key is never used during the audit.

### What one audit does, in order

1. **Checks the local file first.** It verifies the ECDSA signature of `preset.json`. If
   someone edited the file, the audit stops here and raises an alert **without contacting
   the router**.
2. **Reads the router** through the RouterOS API (`/ip/service`, `/ip/firewall/filter`,
   `/user`, `/system/script`).
3. **Compares the configuration field by field** with the trusted copy and reports the
   exact field that changed (for example `/ip/service[telnet].disabled: true -> false`).
   Values that change by themselves, like traffic counters and last login times, are
   ignored.
4. **Checks the signature of every script.** Each script's source code was signed when
   the baseline was saved. Changing even one character makes the ECDSA verification fail.
5. **Reports the result** in the terminal, in a JSON log file, in syslog, and optionally
   through a webhook or an e-mail.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Everything matches the trusted copy |
| `1` | A change or tampering was found (alert) |
| `2` | Error, for example the router could not be reached (this is also treated as an alert) |

---

## 2. Do I need to build it?

**Yes, once for each type of machine.** The tool is written in C++ and needs to be compiled
for the processor where it will run. The only library it needs is **OpenSSL 3**.

| Where it runs | What to build | Section |
|---|---|---|
| Your laptop (Zorin OS / Ubuntu, x86_64) | Normal (native) build | [3.1](#31-laptop-native-build) |
| Raspberry Pi 3B+ with a 64-bit system | Cross-compile for `aarch64` | [3.2](#32-raspberry-pi-cross-compiling-from-the-laptop) |
| Raspberry Pi 3B+ with a 32-bit system | Cross-compile for `armhf` | [3.2](#32-raspberry-pi-cross-compiling-from-the-laptop) |
| Raspberry Pi with a Yocto image | Build with the Yocto layer included here | [3.3](#33-raspberry-pi-yocto-image) |

After building, you get **one file**: `ohboyscan`. Copy it to the machine and it is ready to
use. There is nothing else to install except OpenSSL, which is normally already there.

---

## 3. Building

### 3.1 Laptop (native build)

```bash
sudo apt install build-essential cmake libssl-dev python3 openssl
cmake -S . -B build-native -DCMAKE_BUILD_TYPE=Release
cmake --build build-native -j"$(nproc)"
ctest --test-dir build-native --output-on-failure     # optional: run the unit tests
./build-native/ohboyscan version
```

### 3.2 Raspberry Pi (cross-compiling from the laptop)

"Cross-compiling" means building on the laptop a program that will run on the Raspberry Pi.

```bash
# 1. Install the ARM compilers and qemu (qemu lets you test ARM programs on the laptop)
sudo apt install g++-aarch64-linux-gnu g++-arm-linux-gnueabihf qemu-user-static

# 2. Install OpenSSL for ARM. On Ubuntu, ARM packages come from ports.ubuntu.com:
sudo dpkg --add-architecture arm64 && sudo dpkg --add-architecture armhf
sudo tee /etc/apt/sources.list.d/ports.sources >/dev/null <<'EOF'
Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports
Suites: noble noble-updates noble-security
Components: main universe
Architectures: arm64 armhf
EOF
# Also add the line "Architectures: amd64 i386" to the existing files in
# /etc/apt/sources.list.d/ (ubuntu.sources and the Zorin one), so apt does not
# look for ARM packages in the normal x86 mirror.
sudo apt update && sudo apt install libssl-dev:arm64 libssl-dev:armhf

# 3. Build for 64-bit ARM (Raspberry Pi 3B+ running a 64-bit system)
cmake -S . -B build-aarch64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake
cmake --build build-aarch64 -j"$(nproc)"

# 4. Or build for 32-bit ARM
cmake -S . -B build-armhf -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-linux-gnueabihf.cmake
cmake --build build-armhf -j"$(nproc)"
```

**No sudo?** Run `scripts/bootstrap-toolchain.sh`. It downloads the same official Ubuntu
packages and unpacks them into `./.toolchain` (about 750 MB) without needing root.
`scripts/build-all.sh` uses that folder automatically.

**Build and test everything in one command:**

```bash
scripts/build-all.sh             # laptop + aarch64 + armhf: build, unit tests, 4 test scenarios
scripts/build-all.sh --tls       # same, using the encrypted API (API-SSL)
```

The ARM programs are run on the laptop through qemu, so everything can be tested without
the Raspberry Pi.

> **Compatibility note.** Programs built with Ubuntu 24.04 need glibc 2.38 or newer. They
> run on Raspberry Pi OS Trixie (Debian 13) and on **Yocto Scarthgap (5.0)** or newer, but **not**
> on Yocto Kirkstone (4.0). For a Yocto image, building with Yocto (next section) is the
> safest option.

### 3.3 Raspberry Pi (Yocto image)

A ready Yocto layer is included in `deploy/yocto/meta-ohboyscan`.

```bash
# inside your Poky folder (scarthgap), with meta-raspberrypi already downloaded
source oe-init-build-env build-rpi
bitbake-layers add-layer ../meta-raspberrypi
bitbake-layers add-layer /path/to/ohboyscan_cli/deploy/yocto/meta-ohboyscan
cat >> conf/local.conf <<'EOF'
MACHINE = "raspberrypi3-64"
INHERIT += "externalsrc"
EXTERNALSRC:pn-ohboyscan = "/path/to/ohboyscan_cli"
DISTRO_FEATURES:append = " systemd usrmerge"
VIRTUAL-RUNTIME_init_manager = "systemd"
EOF
bitbake ohboyscan-image
# write the image to the SD card (replace sdX with your card)
bzcat tmp/deploy/images/raspberrypi3-64/ohboyscan-image-*.wic.bz2 | sudo dd of=/dev/sdX bs=4M status=progress conv=fsync
```

The image already contains `/usr/bin/ohboyscan`, an example config in
`/etc/ohboyscan/ohboyscan.conf`, a cron file and a systemd service (disabled by default).

---

## 4. Preparing the MikroTik router

The tool needs a **read-only API user** on the router. Two ready scripts are included:

| Script | Use it when |
|---|---|
| `deploy/mikrotik/setup-lab.rsc` | The auditor is on the normal LAN (laptop at `192.168.88.254`). Does not change interfaces. **This is the one used in our tests.** |
| `deploy/mikrotik/setup.rsc` | Final setup: the Raspberry Pi on a dedicated cable on `ether5` (`10.99.0.2` ⇄ `10.99.0.1`). |

Both scripts:

- create a certificate and turn on the **encrypted API (API-SSL, port 8729)**;
- allow the API **only from the auditor's IP address**;
- create the group `audit` with only `read,api,sensitive` permissions (`sensitive` is needed
  to read the scripts' source code) and the user `ohboyscan`;
- print the certificate **fingerprint** at the end. You will need it in step 5.

**Before running, open the script and change the password** of the `ohboyscan` user.

### How to run a `.rsc` file on the router

1. Open **Winbox** and connect to the router.
2. Open **Files** and drag the `.rsc` file into the window.
3. Open **New Terminal** and type:
   ```
   /import file-name=setup-lab.rsc verbose=yes
   ```
4. The last lines show the services, the user, and the certificate. Copy the
   `fingerprint="..."` value.

Running the script twice is safe. It skips anything that already exists.

### Things we learned on the real router

- **Harden the router before saving the baseline.** RouterOS 6 comes from the factory with
  **telnet, ftp and www enabled**. The tool does not judge whether a setting is safe; it
  only detects changes from the trusted copy. If you save the baseline with telnet on,
  "telnet on" becomes the trusted state. Disable what you don't need first:
  ```
  /ip service set telnet,ftp,www disabled=yes
  ```
- **Set the router clock (NTP).** A router without the correct time creates certificates
  dated 1970. The tool still works because it trusts the certificate by its fingerprint,
  but correct dates make the logs easier to read.
- **After testing, turn off the plain-text API** (port 8728). Only API-SSL is needed:
  ```
  /ip service set api disabled=yes
  ```
- **Scripts in `.rsc` files:** don't use `:local` variables with `verbose=yes`, because each
  line runs on its own and the variable is lost.
- Works with **RouterOS 6.43+ and RouterOS 7**. Tested on an RB750Gr3 (hEX) with RouterOS 6.49.23.

---

## 5. Configuring the tool

The configuration is a simple text file. The default location is
`/etc/ohboyscan/ohboyscan.conf`. You can use another file with `-c file` or with the
`OHBOY_CONFIG` environment variable.

**Example for a laptop without root access** (everything stays in `~/ohboy`):

```bash
mkdir -p ~/ohboy && chmod 700 ~/ohboy
printf '%s\n' 'YOUR-ROUTER-API-PASSWORD' > ~/ohboy/router.pass && chmod 600 ~/ohboy/router.pass
cp deploy/ohboyscan.conf.example ~/ohboy/ohboyscan.conf && chmod 600 ~/ohboy/ohboyscan.conf
export OHBOY_CONFIG=~/ohboy/ohboyscan.conf
```

Then edit `~/ohboy/ohboyscan.conf`. The important lines are:

```ini
[router]
host = 192.168.88.1
user = ohboyscan
password_file = /home/<you>/ohboy/router.pass
tls = true
tls_fingerprint = <the fingerprint printed by the .rsc script>

[paths]
data_dir  = /home/<you>/ohboy/data
log_file  = /home/<you>/ohboy/audit.jsonl
lock_file = /home/<you>/ohboy/ohboyscan.lock
```

Every option is explained in `deploy/ohboyscan.conf.example`.

**Check the connection:**

```bash
./build-native/ohboyscan probe     # logs in and counts the items in each section
./build-native/ohboyscan doctor    # checks OpenSSL, random number source, file permissions
```

`probe` also prints the certificate fingerprint it received. It must be the same value as
the one shown on the router. If the fingerprint is ever different, the tool refuses to
connect and warns about a possible man-in-the-middle (MITM) attack.

---

## 6. Saving the router configuration (the baseline)

This is how you tell the tool **"this is the correct configuration"**.

### Step 1 — create your key pair (only once)

```bash
ohboyscan init --operator victor
```

You will be asked for a **passphrase** twice (at least 8 characters, not shown on screen).
This creates:

| File | What it is |
|---|---|
| `keys/victor.key.pem` | Your **private key**, encrypted with your passphrase (PKCS#8, scrypt + AES-256). Only you can use it. |
| `keys/victor.pub.pem` | Your **public key**. The audit uses it to check signatures. |

Each person who is allowed to approve changes should have their own key. This is what
gives **non-repudiation**: every saved baseline records who signed it, and only the person
who knows the passphrase can sign.

### Step 2 — make sure the router is in a good state

Apply your hardening (see [section 4](#things-we-learned-on-the-real-router)) and check the
configuration in Winbox. Whatever the router has now will become the trusted state.

### Step 3 — save and sign

```bash
ohboyscan preset save --operator victor --comment "after hardening"
```

You type your passphrase, and then the tool:

1. reads `/ip/service`, `/ip/firewall/filter`, `/user` and `/system/script` from the router;
2. removes values that change by themselves (traffic counters, last login, run count);
3. writes everything to `preset.json` in a **canonical format** (sorted keys, fixed
   formatting), so the same configuration always produces exactly the same bytes;
4. **signs each script's source code** separately with your private key;
5. **signs the whole `preset.json`** and stores the signature in `preset.json.sig`;
6. adds a signed line to `history.jsonl` saying who saved it, when, and the file's hash.

Check the result:

```bash
ohboyscan preset show      # summary, sections, scripts and their (r, s) signature values
ohboyscan history          # list of all saved baselines and who signed them
```

### When the router changes on purpose

If you make an **approved** change on the router (for example, a new firewall rule), the
next audit will report it as a change. That is expected. After checking it, save a new
baseline:

```bash
ohboyscan preset save --operator victor --comment "added rule for the new VPN"
```

`history` keeps the full list, so you always know who approved each version. Example from
our tests:

```
[OK ] 2026-11-20T18:37:05Z  victor  preset-save  sha256=da39e7d4ee08cce5  baseline de fabrica + setup-lab
[OK ] 2026-11-20T18:48:18Z  victor  preset-save  sha256=c0be5e49e07bd5c3  hardening: telnet/ftp/www desabilitados
```

### Checking the signature without OhBoyScan

The signatures use standard formats, so anyone can check them with the `openssl` command:

```bash
jq -r .signature preset.json.sig | base64 -d > preset.sig.der
openssl dgst -sha256 -verify keys/victor.pub.pem -signature preset.sig.der preset.json
# Verified OK
```

---

## 7. Running the audit

There is nothing extra to build or prepare. If the baseline is saved, just run:

```bash
ohboyscan audit
```

No passphrase is needed. Example output when everything is fine:

```
OhBoyScan audit @ 2026-11-20T18:40:45Z  roteador=192.168.88.1
  preset: assinatura VÁLIDA (operador victor)
  verificados: 22 itens de configuração, 1 scripts
  tempos: total 355.20 ms | verif. local 0.361 ms | API 349.75 ms | ECDSA scripts 0.277 ms
  resultado: OK — nenhuma divergência
  status: OK
```

Example when someone enabled telnet:

```
  [critical] config-drift: campo alterado
      em /ip/service[telnet].disabled
      antes: true
      agora: false
  status: ALERTA
```

Useful options:

| Option | What it does |
|---|---|
| `--json` | Prints the full report as JSON |
| `--quiet` | Prints nothing when everything is OK (good for cron) |
| `--no-alert` | Does not write logs or send alerts (good for manual tests) |

### Types of findings

| Category | Meaning |
|---|---|
| `config-drift` | A field changed, or an item was added, removed or moved (firewall order matters) |
| `script-tamper` | A script's code changed: its ECDSA signature is no longer valid |
| `script-unsigned` | A new script appeared that is not in the baseline |
| `script-removed` | A signed script was deleted from the router |
| `local-tamper` | `preset.json` on the auditor was changed (the router is not contacted) |
| `router-unreachable` | The router did not answer, login failed, or the TLS fingerprint was wrong |

### Alerts

Every audit is added as one JSON line to `log_file`, and is also sent to syslog. To get
notified, set `command` in the `[alert]` section. The command receives the report as JSON
on its standard input:

```ini
[alert]
# Webhook
command = curl -fsS -m 10 -H 'Content-Type: application/json' --data-binary @- https://hooks.example/ohboyscan
# E-mail (with msmtp)
# command = (printf 'Subject: [OhBoyScan] ALERT %s\n\n' "$OHBOY_HOST"; cat) | msmtp security@example.com
```

---

## 8. Running the audit automatically

Choose **one** of these options:

```bash
# Option A — cron, every 5 minutes
sudo install -m0644 deploy/ohboyscan.cron /etc/cron.d/ohboyscan

# Option B — systemd service (runs the built-in daemon every 300 seconds)
sudo install -m0644 deploy/systemd/ohboyscan.service /etc/systemd/system/
sudo systemctl enable --now ohboyscan

# Option C — run the daemon by hand in the background
ohboyscan daemon --interval 60 --detach --pidfile /run/ohboyscan.pid
```

A lock file prevents two audits from running at the same time.

On the Raspberry Pi, use the default paths (`/etc/ohboyscan`, `/var/lib/ohboyscan`) and
make the keys, `preset.json` and the binary owned by `root` and read-only.

---

## 9. Test results on a real router

**Setup:** MikroTik RB750Gr3 (hEX), RouterOS 6.49.23, laptop running Zorin OS 18 connected
by cable, encrypted API (API-SSL) with the certificate fingerprint pinned.

These are the four test scenarios from the paper (Table 2):

| # | Scenario | What we did | Result |
|---|---|---|---|
| 1 | Control | Nothing (4 audits in a row) | ✅ `rc=0`, no alerts, no false positives |
| 2 | Configuration drift | `/ip service set telnet disabled=no` | ✅ `config-drift` at `/ip/service[telnet].disabled`, `true -> false` |
| 3 | Script tampering | Added 1 space + injected `/tool fetch url=...` | ✅ `script-tamper`, ECDSA verification failed (hash `80185b53…` → `19696667…`) |
| 4 | Local tampering | Changed one value inside `preset.json` | ✅ `local-tamper`, the router was **not** contacted |

Other checks:

- A **wrong TLS fingerprint** was rejected with a "possible MITM" error (`rc=2`).
- After restoring the original script, the audit returned to `rc=0`, so a correct
  restore is recognised.

**Timing** (laptop → hEX):

| Part | Time |
|---|---|
| Full audit | ~355 ms |
| Of which: API connection + TLS handshake on the router | ~350 ms |
| ECDSA verification of `preset.json` | ~0.2 ms |
| ECDSA verification of scripts | ~0.3 ms |

The cryptography is very fast. Almost all of the time is spent talking to the router.

---

## 10. Testing without a router

The project includes a **fake MikroTik API server** (`tests/mock_routeros.py`). It speaks
the real RouterOS API protocol, with or without TLS. The test script runs the same four
scenarios against it:

```bash
tests/scenarios.sh build-native/ohboyscan          # plain API
tests/scenarios.sh build-native/ohboyscan --tls    # API-SSL with fingerprint pinning
```

`scripts/build-all.sh` runs these tests for the laptop and both ARM builds. The ARM
programs run through qemu. Current status: **52/52 unit tests** and **all 4 scenarios**
pass on x86_64, aarch64 and armhf.

---

## 11. Security notes

- **The local file is checked before it is read.** No content of `preset.json` is used
  until its signature is valid.
- **What to audit is part of the signed file.** The list of sections and the ignored fields
  come from the signed baseline, not from the config file. An attacker cannot silently
  "turn off" a section by editing the config.
- **Random numbers.** Each signature uses a fresh random value (nonce) from the Linux
  kernel's random generator. On the Raspberry Pi, this generator is fed by the board's
  hardware random number generator (`ohboyscan doctor` shows `rng_current`). With
  OpenSSL 3.2+, you can set `deterministic_nonce = true` to use RFC 6979 instead.
- **The API user can only read.** Even if the auditor is stolen, the router password
  stored on it cannot change the router.
- **Limits.** Someone with root access on the auditor could replace the public key and the
  baseline. To reduce this risk, use a read-only root filesystem and send the logs to
  another server. Changes are found at the next audit, not instantly. The delay is at most
  the audit interval.

---

## 12. Command reference

```
ohboyscan [-c config] [-d data_dir] <command>

  init --operator NAME [--force] [--passphrase-file FILE]   create a key pair
  keys                                                      list trusted public keys
  preset save --operator NAME [--comment TEXT]              read the router and sign a new baseline
  preset verify                                             check only the local signature
  preset show                                               show the baseline summary
  audit [--json] [--quiet] [--no-alert]                     run one audit
  daemon [--interval SEC] [--detach] [--pidfile FILE]       run audits in a loop (default 300 s)
  history [--no-verify]                                     show the signed history
  probe                                                     test the API login
  doctor                                                    check the environment
  version
```

Environment variables: `OHBOY_CONFIG` (config file), `OHBOY_ROUTER_PASSWORD` (overrides the
password file), `OHBOY_PASSPHRASE` (only for automated tests, don't use it in production).

---

## 13. Project files

```
src/                      C++ source code
  main.cpp                commands
  crypto.*                ECDSA P-256, SHA-256, encrypted keys (OpenSSL)
  routeros_api.*          RouterOS API client (plain and TLS, fingerprint pinning)
  snapshot.*              reads and cleans up the router configuration
  preset.*                saves, signs and verifies the baseline
  audit.*                 compares configuration and checks script signatures
  alert.*                 log file, syslog, alert command
  history.*               signed history of saved baselines
  json.*, config.*, util.*
tests/
  unit_tests.cpp          unit tests
  mock_routeros.py        fake MikroTik API server
  scenarios.sh            the 4 test scenarios
  fixtures/               fake router data
scripts/
  bootstrap-toolchain.sh  ARM compilers without root
  build-all.sh            build and test for laptop, aarch64 and armhf
cmake/toolchains/         cross-compiling settings for aarch64 and armhf
deploy/
  ohboyscan.conf.example  example config with comments
  ohboyscan.cron          cron file
  systemd/                systemd service
  mikrotik/               router setup scripts (setup-lab.rsc, setup.rsc)
  yocto/meta-ohboyscan/   Yocto layer and image
```

---

## 14. How to cite

If you use OhBoyScan or refer to it in a paper, please cite **the software** and, when
it is relevant, **the paper** that describes it.

### The software

```bibtex
@misc{jansen2026ohboyscan,
  author       = {Jansen, Victor Forattini},
  title        = {{OhBoyScan}: A Hardware-Based Auditing Tool for {MikroTik} Routers Using {ECDSA} Signatures},
  year         = {2026},
  month        = nov,
  version      = {1.0.0},
  howpublished = {\url{https://github.com/victorfjansen/ohboyscan_ECDSA}},
  institution  = {Cybersecurity Institute, Pontifical Catholic University of Campinas (PUC-Campinas)},
  note         = {Software, version 1.0.0. C++17 command-line tool, ECDSA P-256 with SHA-256 (OpenSSL 3). Accessed: 2026-11-20},
  keywords     = {Audit trail, MikroTik, ECDSA}
}
```

### The paper

```bibtex
@unpublished{jansen2026hardware,
  author       = {Jansen, Victor Forattini},
  title        = {Hardware-Based Network Auditing and Signature Validation Using {ECDSA}},
  year         = {2026},
  institution  = {Cybersecurity Institute, Pontifical Catholic University of Campinas (PUC-Campinas)},
  note         = {Manuscript. Implementation available at \url{https://github.com/victorfjansen/ohboyscan_ECDSA}},
  keywords     = {Audit trail, MikroTik, ECDSA}
}
```

> **Notes**
> - Both entries use only standard BibTeX types (`@misc`, `@unpublished`), so they work
>   with any style, including the SBC template (`sbc.bst`). Fields a style does not know,
>   such as `version` or `keywords`, are simply ignored.
> - `\url{...}` needs `\usepackage{url}` (or `hyperref`) in your LaTeX preamble.
> - To cite the exact code you used, add the commit hash to `note`, for example
>   `note = {..., commit 90ba4ed}`. Get it with `git rev-parse --short HEAD`.
> - When the paper is published, change `@unpublished` to `@inproceedings` (conference)
>   or `@article` (journal) and add `booktitle`/`journal`, `pages`, `publisher` and `doi`.
