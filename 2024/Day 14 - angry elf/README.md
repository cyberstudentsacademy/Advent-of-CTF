# angry elf

- Published: 12/14/2024 (#14/25 in event)
- Category: Reverse engineering
- Points: 50
- Author: Vip3r

Elf Glaki went rouge! At 2:56 PM EST, he locked up all our flags! Luckily you're not an idiot and you can fix this in 3
minutes. Stop this Angry Elf ASAP!

`nc ctf.csd.lol 1147` (uhh kinda broken but works, will fix soon)

## Attachments

- [kringle](https://files.vipin.xyz/api/public/dl/KhJK0662/advent-of-ctf-csd/angry-elf/kringle)

## Hints

**Hint 1:**

Try decompiling with dogbolt.org, should be a similar process of solving to **screaming**

**Hint 2:**

There is 2 ways of solving, try looking at the decomplication outputs.

## Write-up

<details>
<summary>Reveal write-up</summary>

The first thing we do is to run it through dogbolt to see the source code of the program.

The main part of the program is:

```c
__int64 __fastcall validate_passcode(__int64 a1)
{
  int j; // [rsp+14h] [rbp-1Ch]
  int i; // [rsp+14h] [rbp-1Ch]
  int v4; // [rsp+18h] [rbp-18h]
  char v5[11]; // [rsp+1Dh] [rbp-13h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v4 = 0;
  while ( v4 != 2 )
  {
    if ( v4 )
    {
      for ( i = 0; i <= 10; ++i )
      {
        if ( v5[i] != obfuscated_key[i] )
          return 0LL;
      }
      v4 = 2;
    }
    else
    {
      for ( j = 0; j <= 10; ++j )
        v5[j] = *(_BYTE *)(j + a1) ^ 0x7F;
      v4 = 1;
    }
  }
  return 1LL;
}
// 1253: conditional instruction was optimized away because %var_18.4<3u
// 125D: conditional instruction was optimized away because %var_18.4<3u
// 126D: conditional instruction was optimized away because %var_18.4<2u
// 1279: conditional instruction was optimized away because %var_18.4==1
// 4010: using guessed type _BYTE obfuscated_key[11];
// 1229: using guessed type char var_13[11];

//----- (0000000000001321) ----------------------------------------------------
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *stream; // [rsp+8h] [rbp-A8h]
  char s[16]; // [rsp+10h] [rbp-A0h] BYREF
  char v6[136]; // [rsp+20h] [rbp-90h] BYREF
  unsigned __int64 v7; // [rsp+A8h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  printf("Enter passcode: ");
  __isoc99_scanf("%15s", s);
  if ( strlen(s) == 11 )
  {
    if ( (unsigned int)validate_passcode((__int64)s) )
    {
      puts("Access Granted!");
      stream = fopen("flag.txt", "r");
      if ( stream )
      {
        if ( fgets(v6, 128, stream) )
          printf("Here is your flag: %s\n", v6);
        fclose(stream);
      }
      else
      {
        puts("Error: Could not read flag file.");
      }
    }
    else
    {
      puts("Access Denied!");
    }
    return 0;
  }
  else
  {
    puts("Invalid passcode length!");
    return 1;
  }
}
```

So, to find a key to the app, we need a key that is 11 characters long. Since the code Obfuscates the input passcode
using a bitwise XOR operation with 0x7F and compares the result to a the obfuscated key. So, to find the key, we have to
reverse the obfuscation.

To do this, we can:

Go on CyberChef. Input the numbers that are separated with commas. `(15,13,22,17,24,19,26,12,79,70,92)` Add From Decimal
and put Comma as the delimeter. Add XOR and put `0x7F` aa the key.

The output we get is `pringles09#`. Now input the decrypted text into the NetCat to get the answer:

```bash
jstr$ nc ctf.csd.lol 1147
pringles09#
Enter passcode: Access Granted!
Here is your flag: csd{4N9ry_3lf5_5h0uLdNT_83_M3553D_w1tH}
```

Flag: `csd{4N9ry_3lf5_5h0uLdNT_83_M3553D_w1tH}`

</details>

Write-up by .jstr\_
