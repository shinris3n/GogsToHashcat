# GogsToHashcat.py
Reformats password hashes and salts as stored by Gogs into hashcat 10900 | PBKDF2-HMAC-SHA256 format

# Usage

```
usage: GogsToHashcat.py [-h] [-n Iterations] [-o Output Filename] salt hash

Convert Gogs formatted hash password and salt to hashcat 10900 | PBKDF2-HMAC-SHA256 format.

positional arguments:
  salt                Salt string.
  hash                Hex formatted hash string.

optional arguments:
  -h, --help          show this help message and exit
  -n Iterations       The number of hash function iterations (default is 10000; check Gogs user.go file
                      EncodePassword function).
  -o Output Filename  Output file name.
```

# Example

```
$ python3 GogsToHashcat.py SaltySALT1 18887376aa4ac0d9d89acae7081e0a868a359bd209a60fb399314fe2131e87f264c118879c06fba5cb5bf3b72474a7ff241c -o hashcat.hash
sha256:10000:U2FsdHlTQUxUMQ==:GIhzdqpKwNnYmsrnCB4Khoo1m9IJpg+zmTFP4hMeh/JkwRiHnAb7pctb87ckdKf/JBw=
Hash file successfully written as: hashcat.hash

$ hashcat -m 10900 hashcat.hash /usr/share/wordlists/rockyou.txt --potfile-disable
hashcat (v6.2.5) starting

hashcat -m 10900 hashcat.hash /usr/share/wordlists/rockyou.txt --potfile-disable
hashcat (v6.2.5) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-11th Gen Intel(R) Core(TM) i7-11800H @ 2.30GHz, 2904/5872 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

sha256:10000:U2FsdHlTQUxUMQ==:GIhzdqpKwNnYmsrnCB4Khoo1m9IJpg+zmTFP4hMeh/JkwRiHnAb7pctb87ckdKf/JBw=:password1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:10000:U2FsdHlTQUxUMQ==:GIhzdqpKwNnYmsrnCB4Kh...f/JBw=
Time.Started.....: Sun Aug 21 19:58:06 2022 (0 secs)
Time.Estimated...: Sun Aug 21 19:58:06 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    10664 H/s (7.06ms) @ Accel:768 Loops:256 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests
Progress.........: 3072/14344385 (0.02%)
Rejected.........: 0/3072 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9984-9999
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> dangerous
Hardware.Mon.#1..: Util: 48%

Started: Sun Aug 21 19:58:05 2022
Stopped: Sun Aug 21 19:58:08 2022

```

