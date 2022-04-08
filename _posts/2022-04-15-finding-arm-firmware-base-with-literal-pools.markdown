---
layout: post
title:  "Determining ARM firmware base addresses"
date:   2022-04-15 19:08:00 +0100
categories: ARM firmware
---
![Header Image](/assets/images/2021_03_25-result-plot.png)

[A common problem](https://reverseengineering.stackexchange.com/questions/30157/arm-understanding-a-base-address-when-reversing-firmware) when reversing a firmware blob is to determine the correct offset at which to place the firmware file in memory. Recently, while doing some research into possible solutions, I came across a paper by [Zhu et al.](https://www.sciencedirect.com/science/article/abs/pii/S1742287616000037) The paper proposes an approach that exploits the addresses found in 32bit ARM literal pools to determine the correct firmware offset. I was able to successfully implement and use their approach to determine the offset of two firmware blobs. In this post, I present my implementation: First, I give a quick overview of ARM literal pools. I explain the algorithm concept and provide a detailed analysis of my implementation.

## ARM Literal Pools
Instructions in 32bit ARM can have a length of two or four bytes. This design choice poses some restrictions on how an address can be loaded into a register since a full 32bit address is too long to fit into a single instruction. The following code snippet provides an example of such a scenario:
{% highlight C %}
char foo(char *arr) {
        return arr[0];
}

int _start() {
        char a = foo("Bar Baz Buzz\n");
        char b = foo("Bar Baz Buzz 22\n");
        return a & b;
}
{% endhighlight %}
In order to call function `foo`, the compiler must place the address to the string literals in register `r0`. Since the strings are stored in the `.rodata` section of the application, they are potentially located out of range for PC-relative addressing. Hence, the compiler generates the following code:
```
00008028 <_start>:
    ...
    8034:       e59f0038        ldr     r0, [pc, #56]   ; 8074 <_start+0x4c>
    8038:       ebfffff0        bl      8000 <foo>
    803c:       e1a03000        mov     r3, r0
    8040:       e54b3005        strb    r3, [fp, #-5]
    8044:       e59f002c        ldr     r0, [pc, #44]   ; 8078 <_start+0x50>
    8048:       ebffffec        bl      8000 <foo>
    ...
    8074:       0000807c        .word   0x0000807c
    8078:       0000808c        .word   0x0000808c
```
It places the absolute addresses to the two string literals at the end of the function and uses a PC-relative load instruction to fetch the values from the function trailer into register `r0` before calling `foo`. A collection of such addresses at the end of a function is called a literal pool. For functions that access various different objects in the `.data` or `.rodata` sections, these pools can grow to a significant size. They need not only point to strings, the compiler also generates entries for other things like long program jumps, global variables or even C++ vtables.

Since these literal pools use absolute addresses, they can potentially disclose or narrow down the load address of the firmware blob. In the following section, I describe how this can be accomplished by identifying and linking pool addresses to string literals.

## Algorithm Concept

For our scenario, we assue to have been given a binary firmware blob that operates on string literals, meaning that it accesses string constants in the `.rodata` section. We don't know at which address the firmware is loaded into memory. This makes firmware analysis more complicated because code jumps, variables or strings that rely on absolute addressing cannot be resolved if the firmware is placed at an incorrect location. Hence, the goal of this algorithm is to determine the absolute address at which the firmware image is supposed to be loaded into memory.

### Prerequisites

The algorithm has two prerequisites that must be extracted from the firmware image beforehand:
* The offsets to all string literals that can be identified in the firmware image
* The addresses contained in all identifyable literal pools

Although I list these steps as prerequisite, identifying the literal pool addresses can be considered an important step in the algorithm. The results of these two steps do not necessarily need to be perfect, i.e. can contain false positives, as long as the amount of identified literal pools and string constants is sufficiently high.

### Algorithm Description

Since the compiler always creates literal pools for code that accesses string constants, we can assume that some of the literal pool addresses we identified in the last step must point to the string literals that we found. We can now try out different load addresses and determine the number of literal pool addresses that correctly link up with the identified string constants. The load address that maximizes this function can be considered the correct load address (given that we have correctly selected our candidate load addresses).

This algorithm turns our search into an optimization problem. The advantage of this is that we do not need to find all strings or all literal pools. As long as we find a sufficient number of samples, we can be sure that our algorithm will converge. However, it can also be considered somewhat of a brute-force method, and we need to be smart about what addresses we consider as possible load locations for the firmware. If we select an address range that is too broad, the algorithm will likely not terminate. Fortunately, the non-volatile memory of most embedded chips is rather small compared to the 32 bit address space. Additionally, we can assume the firmware addresses to be aligned to 0x4 or possibly 0x10 to further narrow down the search space.

## Algorithm Implementation

Given the theoretical description in the previous section, simply put, we need to do three things:
* Identify the string constants in the firmware image,
* Identify ARM literal pools in the firmeware image,
* Try out all possible load addresses to determine the one that maximizes the matches between literal pool addresses and string locations.

I implemented each step as part of a Python script. Below, I describe each step in greater detail and explain the implementation I used for each step.

### String Search

I used the following function to find strings in the firmware:
{% highlight Python %}
def find_string_positions(data: bytes, align: int = None) -> List[int]:
    """Find ASCII strings in the firmware blob and return the addresses

    The function uses a regular expression to find the addresses of valid ASCII strings in the firmware.
    If you set the align parameter to something other than None, make sure that the firmware blob is aligned to the
    same value.

    :param data: The firmware blob to search
    :param align: If set to a value other than None, all returned addresses are aligned to this value.
    :return: The addresses of valid strings in the firmware blob
    """
    re_str = br'[\w\s\/*:,;$%&_-]{5,1000}'
    regex = re.compile(re_str)

    str_pos = [m.start() for m in regex.finditer(data)]
    if align is not None:
        str_pos = [p for p in str_pos if p % align == 0]
    return str_pos
{% endhighlight %}

The function operates directly on the firmware blob and outputs all locations, i.e. offsets relative to the beginning of the file, that match the regular expression. The regular expression matches against all strings that consist of alphanumeric characters, spaces, and the list of special characters. This is not necessarily a very precise or exhaustive definition but appears to be sufficient for at least some cases. In order to avoid false positives, the function can optionally filter out all addresses that are not aligned on a four-byte boundary. Since we operate with a 32 bit ARM chip, we can assume all strings placed in the `.rodata` section by the compiler will have this alignment.

## Finding literal pools in the firmware
The second step is to locate literal pools in the firmware image. This step is based on the publication mentioned above but uses a simpler heuristic to accept or reject literal pool candidates. The algorithm uses a dynamically-sized window that is moved across the entire firmware image. With every iteration, the algorithm checks if all values inside the window can be interpreted as absolute addresses pointing into a certain address range. If that is the case, the region is assumed to be a literal pool and the window size is increased until the check fails. All addresses are then added to a buffer, and the window is reset and moved to the next position. Below, I list the complete function:

{% highlight Python %}
def find_address_pools(data: bytes, target_range: Tuple[int, int], win_size: int = WIN_SIZE) -> List[int]:
    """Find ARM 32 bit address pools in the firmware and return the contained addresses

    The function will only perform well if the target_range is narrow. Otherwise a lot of pools will be found.
    Also, the firmware blob must be word-aligned.

    :param data: The firmware blob to search for address pools
    :param target_range: The target address range that the addresses must point to.
    :param win_size: The minimum size that a pool must have
    :return: A list of unique addresses that were found in the pools
    """
    data_arr = np.frombuffer(data, dtype=np.uint32)

    pos = 0
    pool_size = win_size
    candidates = set()
    while True:
        pool = data_arr[pos:pos + pool_size]
        elements_in_range = np.logical_and(pool > target_range[0], pool < target_range[1])
        if not np.all(elements_in_range):
            if pool_size > win_size:
                # The last entry is not valid but we increased the pool size in the last iteration.
                # That means that the last iteration contained a valid pool.
                # Store the pool and reset the window
                pos += pool_size - 1
                candidates.update(pool[:-1])
            else:
                # Entries are not valid and we did not increase the window size in the last iteration
                # Move the window
                pos += 1

            # Reset the pool size to default
            pool_size = win_size

            if pos > len(data_arr) - (pool_size + 0x1):
                break
        else:
            # All items are valid, increase the pool size
            pool_size += 1

    return list(candidates)
{% endhighlight %}

The algorithm accepts the firmware image as binary blob, a target address range, and the minimum window size (which defaults to 3). The target address range parameter represents the range in address space that the values in a candidate literal pool must point to in order to be considered valid. In general, this will be the address range of the flash memory.

The algorithm first converts the binary firmware image into a numpy array of type uint32 with little endianess. Since all addresses inside a pool will be located on a 32 bit boundary, we can safely perform this conversion. The loop begins with the first 

