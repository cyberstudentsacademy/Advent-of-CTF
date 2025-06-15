# resa

- Published: 12/09/2024 (#9/25 in event)
- Category: Cryptography
- Points: 80
- Author: Vip3r

**Elf Theodred:** Hey, I’m testing out a new... _<yap yap yap>_

**You:** What? You lost me at "Hey, I’m testing."

**Elf Theodred:** What I _said_ was, I encrypted... _<yap yap yap>_ and missing `q`.

**You:** Resa? Vesa? Are we talking about monitors or cybersecurity? And what’s this about a missing `e` and `q`? Is
that supposed to be a type of screw? Huh?

**Elf Theodred:** I’m not repeating myself to an intern. Figure it out, bud. And if you heard a word I said, it's
under 50.

## Attachments

- [enc](https://files.vipin.xyz/api/public/dl/RuhE4DVV/advent-of-ctf-csd/resa/enc)

## Hints

**Hint 1:** Elf Theodred was talking about RSA! To decrypt RSA, you need a `P`, `Q`, `E`, and `C`, but we are missing
the `E` and `Q`. How do we know what the `E` is though? How do we get Q? Did Elf Theodred say something?

**Hint 2:** Ok, the E is supposedly under 50 and must be a valid coprime number. Also, n = p\*q which means we can just
divide to get `Q` That should be narrowing enough for us to solve!

## Write-up

<details>
<summary>Reveal write-up</summary>

We are missing `e` & `q` as stated by the description and `e` is under 50. A typical way to solve RSA if we had all the
values is with a script like this (Credit:
[Practical CTF](https://book.jorianwoltjer.com/cryptography/asymmetric-encryption/rsa))

```python
e = <value>
p = <value>
q = <value>
n = p*q

phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

Now to obtain `q` it's pretty simple in this case, we just need to divide `n` by `p` which is as simple as...

```python3
>>> q = n//p
>>> print(q)
155694605282054119425521475624300384083466178240627480935854427486918260095552504358478493985940907113009654254657147586057507955661767483844303106556370030901659779958849987047274410348258176148315164774766854079870085660650560858927588536846613174753328861645595054240895935716160988886137891728973522588917
>>>
```

Now we have `q`, now the last value needed is `e`. To accomplish this I wrote a python script to bruteforce.

```python
from Crypto.Util.number import long_to_bytes

# our values
c = 7834381455537086069556470828674580173937271064256312815617230923582264273260067511896680320170885743343862894164014864043792487985706669274975353978277862462944814782646749746217479200710773218743409525658958249817055354592575831865920206596021699022326281524908299055420849742148757177093582285192053105592180465511200588277457610702671508363048935552446809692594715753573724603294565113603946429767347234628199252177612170759392617992009035004668823723769453952068616628571785811538463850603629779083508146990944772896050051747702814005551146368404685501836088557927084895438654990821206561992369510510301944786242
p = 95035264145462998106373959950852388512916398417336694051973007035267892127571038290551358518210018988802168144062568058000141570285306734135476955708641860308084865175837570650537276267265396611644179740194499506782555051319215145789689879081854479885459274078337276115880870922739027746148771680782305865397
q = 155694605282054119425521475624300384083466178240627480935854427486918260095552504358478493985940907113009654254657147586057507955661767483844303106556370030901659779958849987047274410348258176148315164774766854079870085660650560858927588536846613174753328861645595054240895935716160988886137891728973522588917

n = p * q
phi = (p - 1) * (q - 1)

# Brute-forcing `e` to find the flag
for e in range(1, 50):
    try:
        d = pow(e, -1, phi) # RSA Magic
        m = pow(c, d, n)
        flag = long_to_bytes(m)

        if b'csd{' in flag:
            print(f"FLAG: {flag.decode()}")
            break
    except ValueError:
        continue
```

And running it we get...

```bash
$ python3 sol.py
FLAG: csd{V3sA_R3sa_RSa?_1D3k}
```

Flag: `csd{V3sA_R3sa_RSa?_1D3k}`

</details>

Write-up by zarnex
