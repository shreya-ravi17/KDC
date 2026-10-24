"""KDC server.

  python kdc_server.py init Alice Bob      # create keys/Alice.key, keys/Bob.key
  python kdc_server.py serve --port 5000   # run the KDC

The .key files are the master keys. Give Bob.key to Bob by a SECURE side
channel (USB, in person...). That is the "out-of-band registration" step.
"""
import argparse, glob, os
from kdc_sim import KDC
from kdc_sim.crypto_utils import generate_key
from kdc_sim.net import serve_kdc, load_key


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("names", nargs="+"); i.add_argument("--dir", default="keys"); i.add_argument("--force", action="store_true")
    s = sub.add_parser("serve"); s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int, default=5000)
    s.add_argument("--dir", default="keys"); s.add_argument("--lifetime", type=int, default=600)
    a = p.parse_args()

    if a.cmd == "init":
        os.makedirs(a.dir, exist_ok=True)
        for n in a.names:
            path = os.path.join(a.dir, n + ".key")
            if os.path.exists(path) and not a.force:
                print(f"{path} exists (use --force to overwrite)"); continue
            with open(path, "w") as f:
                f.write(generate_key().hex())
            print("created", path)
        return

    kdc = KDC(session_lifetime=a.lifetime)
    for path in glob.glob(os.path.join(a.dir, "*.key")):
        name = os.path.basename(path)[:-4]
        kdc.load_key(name, load_key(path)); print("registered:", name)
    if not kdc._master_keys:
        print("No keys found. Run:  python kdc_server.py init Alice Bob"); return
    print(f"KDC listening on {a.host}:{a.port}  (session lifetime {a.lifetime}s)")
    serve_kdc(kdc, a.host, a.port)


if __name__ == "__main__":
    main()
