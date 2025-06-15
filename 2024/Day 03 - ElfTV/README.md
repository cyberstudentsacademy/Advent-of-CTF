# ElfTV

- Published: 12/03/2024 (#3/25 in event)
- Category: Reverse engineering
- Points: 55
- Author: Vip3r

Santa’s ElfTV license key checker got leaked! Finally, a break for a broke elf like you, starving for that sweet, sweet
elf dopamine. The catch? You’ve got to reverse-engineer Santa’s “state-of-the-art” security to unlock it. Think you’re
smarter than the guy who still uses reindeer for transportation? Prove it and claim your ElfTV fix!!!!

Connect using `nc ctf.csd.lol 1001`

## Attachments

- [source.rs](https://files.vipin.xyz/api/public/dl/iPDnjAOH/advent-of-ctf-csd/Day%203%20-%20ElfTV/source.rs)

## Hints

**Hint 1:** Look closely at each function. How does it contribute to validating the key?

**Hint 2:** The Fibonacci sequence is used in the key validation, but it doesn't behave as the Elves expected. Examine
the function and figure out why it isn't producing the standard Fibonacci numbers.

## Write-up

<details>
<summary>Reveal write-up</summary>

Let's take a look at the source!

```rust
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;

fn supasecurefibberdachicheckerthing(n: usize) -> Vec<u64> {
    let mut fib: Vec<u64> = vec![0, 1];
    for i in 2..n {
        let next = fib[i - 1].checked_add(fib[i - 2]).unwrap_or(0);
        fib.push(next);
    }
    fib
}

fn validate_license_key(key: &str) -> bool {
    if !key.starts_with("XMAS") {
        return false;
    }

    if key.len() != 12 {
        return false;
    }

    let ascii_sum: u32 = key.chars().skip(4).take(5).map(|c| c as u32).sum();
    if ascii_sum != 610 {
        return false;
    }

    let fib_482 = supasecurefibberdachicheckerthing(483)[482];
    let fib_last_3 = fib_482 % 1000;

    let key_last_3: u16 = match key[9..12].parse() {
        Ok(num) => num,
        Err(_) => return false,
    };

    if key_last_3 != fib_last_3 as u16 {
        return false;
    }

    true
}

fn win() {
    let flag_path = Path::new("flag.txt");

    if let Ok(file) = File::open(flag_path) {
        let mut buf_reader = io::BufReader::new(file);
        let mut flag = String::new();
        if buf_reader.read_line(&mut flag).is_ok() {
            println!("🎄 Ho Ho Ho!, go watch some ELFTV!: {}", flag.trim());
        } else {
            println!("smth went wrong contact vip3r with error (flag-file-1)");
        }
    } else {
        println!("smth went wrong contact vip3r with error (flag-file-2)");
    }
}


fn main() {
    println!("🎄 Welcome to the ElfTV XMAS-license key checker!");
    println!("Please enter your license key:");

    let stdin = io::stdin();
    let mut input = String::new();
    let mut stdout = io::stdout();

    if stdin.read_line(&mut input).is_ok() {
        let key = input.trim();
        if validate_license_key(key) {
            win();
        } else {
            writeln!(stdout, "Ho ho ho! Try again.").unwrap();
        }
    } else {
        writeln!(stdout, "Failed to read the input!").unwrap();
    }
}
```

So the goal of this challenge is to piece together a license key to get the flag. Let's start by analyzing each function
used to check for the license key.

```rust

fn validate_license_key(key: &str) -> bool {
    if !key.starts_with("XMAS") {
        return false;
    }

    if key.len() != 12 {
        return false;
    }

    let ascii_sum: u32 = key.chars().skip(4).take(5).map(|c| c as u32).sum();
    if ascii_sum != 610 {
        return false;
    }

    let fib_482 = supasecurefibberdachicheckerthing(483)[482];
    let fib_last_3 = fib_482 % 1000;

    let key_last_3: u16 = match key[9..12].parse() {
        Ok(num) => num,
        Err(_) => return false,
    };

    if key_last_3 != fib_last_3 as u16 {
        return false;
    }

    true
}
```

This function in the source is what checks if the license key is correct or not.

```rust
if !key.starts_with("XMAS") {
        return false;
    }
```

This first check is pretty straight forward, it checks if the string starts with XMAS

```rust
if key.len() != 12 {
        return false;
    }
```

The next check above is looking at if the key is 12 characters, so now we have general idea on how the license key
should look like. `XMAS********`

```rust
let ascii_sum: u32 = key.chars().skip(4).take(5).map(|c| c as u32).sum();
if ascii_sum != 610 {
    return
```

Now it is starting to get tricky to understand, lets go over it!

1. `key.chars()`: Turns the string into a iterator of is characters
2. `.skip(4)`: Skips the first 4 chars
3. `.take(5)`: Takes the next 5 characters after skipping the first 4.
4. `.map(|c| c as u32)`: Maps each character in this slice to its ASCII value (as a u32 integer).
5. `.sum()`: Takes the sum of these ASCII values.
6. `let ascii_sum: u32 = ...;`: Saves the sum in a variable ascii_sum.
7. `if ascii_sum != 610 {`: Checks if the sum of these ASCII values is not equal to 610.

So at this point we need to find 5 characters that add up to 610 which is nice since it is even. So I wrote a Python one
liner `print(chr(int(610 / 5)) * 5)` which outputs `zzzzz`. So our license key should look like `XMASzzzzz***` so far.

```rust
let fib_482 = supasecurefibberdachicheckerthing(483)[482];
let fib_last_3 = fib_482 % 1000;

let key_last_3: u16 = match key[9..12].parse() {
    Ok(num) => num,
    Err(_) => return false,
};

if key_last_3 != fib_last_3 as u16 {
    return false;
}
```

Now the final check had me confused, I was looking very surface level and thought the key was just the last 3 digits of
the Fibonacci sequence for the 482 number (which is 041) but it didn't work. As I look in deeper, it seems as the codes
implementation of the Fibonacci check is faulty because of this

- The Function is computing the digits using `u64` integers
- `u64` can hold up to 2^64−1≈1.84×10^19
- And by the 94th number is overflows that limit changing f'ing up the rest of the numbers.

So to get the correct number, I modified the code to just print out the last 3 digits.

```rust
fn main() {
    fn supasecurefibberdachicheckerthing(n: usize) -> Vec<u64> {
        let mut fib: Vec<u64> = vec![0, 1];
        for i in 2..n {
            let next = fib[i - 1].checked_add(fib[i - 2]).unwrap_or(0);
            fib.push(next);
        }
        fib
    }

    let fib_482 = supasecurefibberdachicheckerthing(483)[482];
    let fib_last_3 = fib_482 % 1000;

    println!("last 3 digits: {}", fib_last_3);
}
```

And running it...

```bash
$ rustc test.rs
$ ./test
last 3 digits: 738
```

So now we have our full license key: `XMASzzzzz738`. Lets try it!

```bash
$ nc ctf.csd.lol 1001
🎄 Welcome to the ElfTV XMAS-license key checker!
Please enter your license key:
XMASzzzzz738
🎄 Ho Ho Ho!, go watch some ELFTV!: csd{Ru57y_L1c3N53_k3Y_CH3Ck3r}
```

Flag: `csd{Ru57y_L1c3N53_k3Y_CH3Ck3r}`

</details>

Write-up by zarnex
