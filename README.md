# Symmetric Key Distribution with a KDC (Simulation)

A Python simulation of a **Key Distribution Center** that lets Alice obtain a
session key to talk securely with Bob, using the **Needham-Schroeder symmetric
protocol** (with ticket lifetime/expiry as in the Denning fix).

## Setup & run
```bash
pip install -r requirements.txt
python demo.py                      # full walkthrough + 7 scenarios
python -m unittest discover -s tests -v   # 15 tests
```

## Web frontend
Open `frontend/index.html` in Chrome, Edge or Firefox (just double-click). It runs the same protocol visually with real AES-GCM via the browser's Web Crypto API: step-by-step message flow, key panel, secure chat, and attack buttons (replay, tamper, eavesdrop, unregistered user, key expiry).

## Live mode: Alice and Bob on different computers
Three programs talk over TCP: `kdc_server.py`, `bob.py`, `alice.py`.

```bash
# 1. KDC machine (once): create master keys
python kdc_server.py init Alice Bob
#    Give keys/Bob.key to Bob by a secure side channel (USB / in person).
# 2. KDC machine: run the KDC
python kdc_server.py serve --port 5000
# 3. Bob's machine (needs keys/Bob.key):
python bob.py --key keys/Bob.key --port 5001      # prints the IP to give Alice
# 4. Alice's machine (needs keys/Alice.key):
python alice.py --kdc KDC_IP:5000 --peer-addr BOB_IP:5001
```
Both screens print the same *session key fingerprint* when the handshake works, then you can chat. Chat messages carry sequence numbers, so a replayed message is rejected.
Notes: same Wi-Fi/hotspot (some college Wi-Fi blocks device-to-device traffic), allow Python through the Windows firewall, and keep PC clocks correct (tickets expire).

## Project layout
| File | Purpose |
|---|---|
| `kdc_sim/kdc.py` | KDC: registers principals, generates session keys, builds tickets |
| `kdc_sim/client.py` | Client (Alice/Bob): initiator + responder logic, secure messaging |
| `kdc_sim/crypto_utils.py` | AES-256-GCM encrypt/decrypt, key & nonce generation |
| `kdc_sim/network.py` | Simulated network that logs (and can tamper with) every message |
| `frontend/index.html` | Interactive visual simulation (no install needed) |
| `kdc_sim/net.py` | TCP layer: KDC server, remote proxies, chat |
| `kdc_server.py`, `alice.py`, `bob.py` | Live programs for real-time use |
| `demo.py` | Demonstration of normal flow and attacks |
| `tests/test_kdc.py` | Unit tests |

## Protocol
Ka, Kb = master keys shared with the KDC (registered out-of-band).
Ks = fresh session key. N1, N2 = nonces.

```
1. A -> KDC : A, B, N1
2. KDC -> A : E(Ka, [Ks, B, N1, expires, Ticket])
              Ticket = E(Kb, [Ks, A, timestamp, expires])
3. A -> B   : Ticket
4. B -> A   : E(Ks, N2)
5. A -> B   : E(Ks, N2 - 1)
   then       E(Ks, message) in both directions
```

## Security properties
| Threat | Defence |
|---|---|
| Eavesdropping | All keys/messages are AES-GCM encrypted; master keys never sent |
| Impersonation to KDC | Only registered principals; reply decryptable only with Ka |
| Replay of KDC reply | N1 in reply must match Alice's request |
| Replay of ticket to Bob | Bob tracks seen tickets + expiry check |
| Old/compromised key reuse | Session key has a lifetime; new Ks per session |
| Tampering | GCM authentication tag fails -> message rejected |
| Ticket stolen by another user | Ticket binds identity A; Bob checks sender |
| Bob proves Alice has Ks | Steps 4-5 challenge-response |

## Limitations (discuss in report)
- KDC is a single point of failure and fully trusted.
- Master keys assumed distributed securely out-of-band.
- Sockets are plain TCP (no TLS); only protocol data is encrypted. Ticket replay memory is lost on restart.
- Clocks assumed loosely synchronised for expiry checks.
