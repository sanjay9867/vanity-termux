#!/usr/bin/env python3
import sys, time, hashlib
from ecdsa import SigningKey, SECP256k1
import base58
from multiprocessing import Pool, cpu_count, Manager

def pubkey_to_address(pubkey_bytes, testnet=False):
    """Convert serialized public key to a Bitcoin address."""
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    prefix = b'\x6f' if testnet else b'\x00'
    payload = prefix + ripe
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + chk).decode()

def worker(args):
    """One worker process: keep generating until found."""
    prefix, testnet, report_q = args
    attempts = 0
    start = time.time()
    while True:
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        pub = b'\x04' + vk.to_string()
        addr = pubkey_to_address(pub, testnet)
        attempts += 1
        if attempts % 100000 == 0:
            report_q.put((attempts, addr, time.time()-start))
        if addr.startswith(prefix):
            # Found it
            return sk.to_string().hex(), addr, attempts, time.time()-start

def reporter(report_q):
    """Report status from workers."""
    last = time.time()
    total = 0
    while True:
        try:
            attempts, addr, elapsed = report_q.get(timeout=1)
            total += 100000
            print(f"[{int(elapsed)}s] {total} tries — latest: {addr}")
        except:
            # no new report
            if time.time() - last > 5:
                last = time.time()
        # loop until main process ends

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 vanity_termux.py PREFIX [--testnet]")
        sys.exit(1)
    prefix = sys.argv[1]
    testnet = "--testnet" in sys.argv

    print(f"Searching for address starting with '{prefix}' on {'testnet' if testnet else 'mainnet'}")
    manager = Manager()
    report_q = manager.Queue()

    # Prepare worker args
    workers = cpu_count()
    args = [(prefix, testnet, report_q)] * workers

    # Start reporter process
    from multiprocessing import Process
    rep = Process(target=reporter, args=(report_q,), daemon=True)
    rep.start()

    # Start pool
    with Pool(workers) as pool:
        result = pool.map(worker, args)[0]

    privkey_hex, address, attempts, elapsed = result
    print("\n✅ Found!")
    print(f"Address: {address}")
    print(f"Private key (hex): {privkey_hex}")
    print(f"Attempts: {attempts:,}")
    print(f"Time: {elapsed:.1f}s")

if __name__ == "__main__":
    main()
