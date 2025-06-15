# Epochrypt

- Published: 12/06/2024 (#6/25 in event)
- Category: Cryptography
- Points: 70
- Author: Vip3r

It's time to test out Tibel Elf's new encryption method. He says once you encrypt it, you can't unencrypt it. Sureeee...
Connect with `nc ctf.csd.lol 3551`.

## Attachments

- [main.py](https://files.vipin.xyz/api/public/dl/U4c32yT7/advent-of-ctf-csd/epochrypt/main.py)

## Hints

**Hint 1:** Tibel Elf thinks since we can't go back in time we can't reverse the encryption... How does the encryption
utilize time to encrypt?

**Hint 2:** It seems to use epoch with XOR. What if we guess what epoch time it is XORing the string? Python may help
script a solution.

## Write-up

<details>
<summary>Reveal write-up</summary>

Lets look at `main.py`.

```python
#!/usr/local/bin/python
import time
import base64 as b64
from pwn import xor

def epochrypt(enc):
    bits = bytes([(b + 3) % 256 for b in enc])
    based = b64.b64encode(bits)
    epc = str(int(time.time())).encode()
    final = xor(based, epc)
    print(final.hex())


def menupage():
    print("Epochrypt v1.0")
    print("\"The Dynamic Encryption Method\"")
    print("------------------------------------")
    print("1. Encrypt Text")
    print("2. View Encrypted Flag")
    print("3. Check Flag")
    print("4. Exit Program")


try:
    while True:
        menupage()
        option = input("Enter option here: ")
        if option == "1":
            textToEncrypt = input("Enter String: ")
            epochrypt(textToEncrypt.encode())
            exit(0)
        if option == "2":
            with open("/app/flag.txt", "rb") as file:
                flag = file.read()
            epochrypt(flag)
            exit(0)
        if option == "3":
            checkFlag = input("Enter flag here to check: ")
            with open("/app/flag.txt", "rb") as file:
                flag = file.read()
                if flag in (checkFlag + "\n").encode():
                    print("Correct! You got it, now go submit that thang.")
                    exit(0)
                else:
                    print("*BUZZ* That ain't it bud :(")
                    exit(0)
        if option == "4":
            print("bye bye!")
            exit(0)

except KeyboardInterrupt:
    print("CTRL + C detected, Quitting program...")
```

Most of this is straight forward with all the features, but the main thing we need to focus on is the `epochrypt()`
function.

```py
def epochrypt(enc):
    bits = bytes([(b + 3) % 256 for b in enc])
    based = b64.b64encode(bits)
    epc = str(int(time.time())).encode()
    final = xor(based, epc)
    print(final.hex())
```

This may be a small function but it packs a punch! Lets go over this line by line.

```python
bits = bytes([(b + 3) % 256 for b in enc])
```

The first line is pretty much adding 3 to every characters ASCII values, kinda treating it like a Caeser Cipher. Using
this one liner `print(bytes([(b + 3) % 256 for b in b'hello']))`, we see that _hello_ becomes _khoor_.

```python
based = b64.b64encode(bits)
```

In this line it takes the items from `bits` and _Base64_ encodes them.

```python
epc = str(int(time.time())).encode()
final = xor(based, epc)
```

Now here comes the interesting part, first it takes the current Unix _Epoch_ time and turns them into a int to strip the
decimal at the end, after that it XOR's it by `Based`. This is probably where it gets the _"The Dynamic Encryption
Method"_ name from because it XOR's it by _Epoch_ time (The amount of time since January 1, 1970) so it will never be
the same again.

```python
print(final.hex())
```

And then finally it outputs the text in Hex! Lets try it out for ourself.

```bash
$ nc ctf.csd.lol 3551
Epochrypt v1.0
"The Dynamic Encryption Method"
------------------------------------
1. Encrypt Text
2. View Encrypted Flag
3. Check Flag
4. Exit Program
Enter option here: 1
Enter String: Hello
62055b405201710d6507

$ nc ctf.csd.lol 3551
Epochrypt v1.0
"The Dynamic Encryption Method"
------------------------------------
1. Encrypt Text
2. View Encrypted Flag
3. Check Flag
4. Exit Program
Enter option here: 1
Enter String: Hello
62055b405201710d6406
```

Here I tried to encrypt Hello twice, notice how it is different. This is because it XOR's with the Epoch time which
changes every second. Now we gotta figure out how to reverse the text. Here is what I wrote

```py
from pwn import *
from base64 import b64decode
from time import sleep, time
```

I started off by importing **_pwntools_** to connect to the server and to items, then imported **_time_** to grab the
_epoch_ time and use `sleep()`

```py
target = remote("ctf.csd.lol", 3551) # Connecting to the server
sleep(2) # Pausing the program
target.sendline("2") # Sending 2 to print out flag
epc = str(int(time())) # Grabbing the epoch time exactly when 2 is sent
sleep(2) # Pausing for 2 seconds
```

So I did write comments above on what each line does, but the general idea on what this part of the script does it to
grab the epoch when it enters 2 so we have the exact epoch time to XOR with.

One thing I had noticed was that the flag when pressing option 2 always started with `6b5969` so now we can just

```py
response = target.recv(1000).decode()  # Receive up to 1000 bytes
start_idx = response.find("6b5969")  # Find the position of "6b5969"
enc_flag = response[start_idx:].split("\n")[0].strip()  # Extract flag from marker to end of line
```

Now we have that extraction, all we need to do now is to write the next part of the script to reverse the encryption.

```py
flag = bytes([(b - 3) % 256 for b in b64decode(xor(bytes.fromhex(enc_flag), epc))]) # Very Concise 1 liner that reverses the epochrypt operations
print(f"Flag: {flag.decode()}") # Decodes flag so output wouldn't be b''
```

So the full solution is...

```python
from pwn import *
from base64 import b64decode
from time import sleep, time

target = remote("ctf.csd.lol", 3551)
sleep(2)
target.sendline("2")
epc = str(int(time()))
sleep(2)
response = target.recv(1000).decode()
start_idx = response.find("6b5969")
enc_flag = response[start_idx:].split("\n")[0].strip()
flag = bytes([(b - 3) % 256 for b in b64decode(xor(bytes.fromhex(enc_flag), epc))])
print(f"Flag: {flag.decode()}")
```

Running it...

```bash
$ /bin/python3 /home/zarnex/advent_of_ctf/epochrypt/solution.py
[+] Opening connection to ctf.csd.lol on port 3551: Done
/home/zarnex/advent_of_ctf/epochrypt/solution.py:8: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline("2")
/home/zarnex/.local/lib/python3.12/site-packages/pwnlib/util/fiddling.py:335: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  strs = [packing.flat(s, word_size = 8, sign = False, endianness = 'little') for s in args]
Flag: csd{d3F0_M4d3_8y_4N_3lf}
```

Yes! But lets double check the flag...

```bash
$ nc ctf.csd.lol 3551
Epochrypt v1.0
"The Dynamic Encryption Method"
------------------------------------
1. Encrypt Text
2. View Encrypted Flag
3. Check Flag
4. Exit Program
Enter option here: 3
Enter flag here to check: csd{d3F0_M4d3_8y_4N_3lf}
Correct! You got it, now go submit that thang.
```

Flag: `csd{d3F0_M4d3_8y_4N_3lf}`

</details>

Write-up by zarnex
