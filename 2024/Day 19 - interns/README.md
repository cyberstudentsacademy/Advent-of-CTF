# interns

- Published: 12/19/2024 (#19/25 in event)
- Category: Cryptography
- Points: 150
- Author: Vip3r

Interns often struggle with creating things, but Elf Bharmeesh insists you give it a shot. You refused initially, but he
went behind your back and encrypted your password, wrapping it in csd{}. Now, you’ve forgotten the password. It’s time
to crack it!

## Attachments

- [enc.py](https://files.vipin.xyz/api/public/dl/OIQB--66/advent-of-ctf-csd/intern-test/enc.py)
- [ciphertext.txt](https://files.vipin.xyz/api/public/dl/2JQTuHVu/advent-of-ctf-csd/intern-test/ciphertext.txt)
- [public.txt](https://files.vipin.xyz/api/public/dl/_SxcgxKg/advent-of-ctf-csd/intern-test/public.txt)

## Hints

**Hint 1:**

The first thing you need to do is factor N. You also get the partial `p` and `q` bits. Use tools like sage or a NFS
sieve. Feel free to ask the challenge author questions via Modmail!

**Hint 2:**

Read the program. If you are having trouble understanding RSA solve **_resa_** first. Feel free to ask the challenge
author questions via Modmail!

## Write-up

<details>
<summary>Reveal write-up</summary>

I first thought there was a more graceful way to factor `N` with leaked `p` and `q`, but I gave up and just factored
with **Cado-NFS** which is as simple as:

```bash
$ make
$ ./cado-nfs.py <N>
```

Then wait forever for it to factor... Eventually I got 3 primes: `p`, `q`, `r`

```txt
p = 196193902291230366369929504455328667247
q = 330729152607130810754863800538364851519
r = 321006911433478242108053772673636286011
```

I did confirm it was correct by doing 2 things

- Adding/Asserting the primes, checking if they multiply to N.
- Comparing the partial salt to my own generated salt from the primes

At this point, we have **N** factored. Now, we need a mask. Using Python for brute-forcing would take too long, so I had
GPT write a **C** script to brute-force **step 3** following the requirements needed for the task.

The biggest issue I encountered was with the first iteration of the mask script. I initially instructed GPT to make a
script, which I fixed up, but it was designed to quit after finding **a** mask. The problem was that there were **more
than one mask**. It wasn’t until later that I realized the mask was wrong but met the requirements. I had to rewrite the
script to brute-force all the way through to find **all the masks** that met the requirements.

After generating the masks, I used my script to check if they were correct. This iterative process helped me identify
the correct masks. Below is the output of the script that generated the **3 masks**.

Since the script is around **170 lines**, I won't paste it here. You can download it [here](./step3brute.c).

```bash
$ time ./brute_mask 14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622227351205298

# Truncated for brevity

[*] Progress: 4286000000 / 4294967296 (99.79%)
[*] Progress: 4287000000 / 4294967296 (99.81%)
[*] Progress: 4288000000 / 4294967296 (99.84%)
[*] Progress: 4289000000 / 4294967296 (99.86%)
[*] Progress: 4290000000 / 4294967296 (99.88%)
[*] Progress: 4291000000 / 4294967296 (99.91%)
[*] Progress: 4292000000 / 4294967296 (99.93%)
[*] Progress: 4293000000 / 4294967296 (99.95%)
[*] Progress: 4294000000 / 4294967296 (99.98%)

[*] Finished brute force. Found 3 matches.

[Match #1]
    mask_candidate = 0x8252FF0B (2186477323)
    step3 = 14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622229537622713

[Match #2]
    mask_candidate = 0x966321D0 (2523079120)
    step3 = 14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622229740049506

[Match #3]
    mask_candidate = 0xC51C22A3 (3306955427)
    step3 = 14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622228375918353
./brute_mask   4645.55s user 3.10s system 99% cpu 1:17:28.97 total
```

Now we have our mask, I then started to extract the flag out now. My script is below with comments:

```python
from sage.all import Zmod, pari
from Crypto.Util.number import long_to_bytes

# modular arithmetic setup
N = 20829189282001863372322428196733308195464709019397028562940874561583326274287129648306568901830962480022928679678123
p = 196193902291230366369929504455328667247
q = 330729152607130810754863800538364851519
r = 321006911433478242108053772673636286011

# step3 values from our brute force
step3_values = [
    14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622229537622713,
    14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622229740049506,
    14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622228375918353,
]

# pari primes used for optimization, pari seems to speed up sage like crazy which i came across from https://doc.sagemath.org/html/en/reference/spkg/pari.html
x = pari.addprimes([p, q, r])

# salt is the sum of p and q
salt = p + q

# get modular roots (nth root of value mod mod), returns all roots
def get_roots(value, n, mod):
    try:
        return list(Zmod(mod)(value).nth_root(n, all=True))
    except:
        return []

# process a single step3 value to find the flag
def find_flag(step3):
    step2_roots = get_roots(step3, 5, N)
    if not step2_roots:
        return None
    for step2 in step2_roots:
        step1 = (step2 - salt) % N
        step1_roots = get_roots(step1, 3, N)
        if not step1_roots:
            continue
        for m in step1_roots:
            try:
                plaintext = long_to_bytes(int(m))
                if b'csd' in plaintext:  # flag format starts with 'csd'
                    return plaintext.decode()
            except:
                pass
    return None

# loop through step3 values to find the flag
for step3 in step3_values:
    flag = find_flag(step3)
    if flag:
        print(f"Flag: {flag}")
        break
```

Running it...

```bash
$ sage sol2.sage
Flag: csd{dH4R_dh4r_4Nt1_P1R4cY_5CR33n}
```

Flag: `csd{dH4R_dh4r_4Nt1_P1R4cY_5CR33n}`

</details>

Write-up by zarnex
