#include <string>
#include <iostream>

#define ROTL32(x,n) ((x) << n | (x) >> (32-n))

#define MIX(h,d) \
  d *= 0xcc9e2d51; \
  d = ROTL32(d, 15); \
  d *= 0x1b873593; \
  h ^= d; \
  h = ROTL32(h, 13); \
  h = h * 5 + 0xe6546b64;

#define FINAL_MIX(h) \
  h ^= h >> 16; \
  h *= 0x85ebca6b; \
  h ^= h >> 13; \
  h *= 0xc2b2ae35; \
  h ^= h >> 16;

uint32_t caml_hash_mix_string(uint32_t h, std::string s) {
    size_t len = s.length();
    size_t i;
    uint32_t w;

    for (i = 0; i + 4 <= len; i += 4) {
        w = *((uint32_t *) &s[i]);
        MIX(h, w);
    }
    w = 0;
    switch (len & 3) {
        case 3: w = s[i+2] << 16;
        case 2: w |= s[i+1] << 8;
        case 1: w |= s[i];
                MIX(h, w);
    }
    h ^= len;
    return h;
}

uint32_t caml_hash(std::string s) {
    uint32_t h = caml_hash_mix_string(0, s);
    FINAL_MIX(h);
    return h & 0x3FFFFFFFU;
}

int main() {
    std::string flag;
	uint32_t toStringHash = caml_hash("toString");
    uint64_t st[8] = {8258240093, 32059146620, 59424680571, 16501626909, 10391056299, 39819521706, 63129310438};
    std::string start = "union{h";
    std::string A = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    for(size_t i = 0; i < 7; ++i) {
        std::cout << st[i] << std::endl;
        int64_t t5 = A.find(start[i]);
        for (int t1 = 0; t1 < 64; t1++) {
        for (int t2 = 0; t2 < 64; t2++) {
        for (int t3 = 0; t3 < 64; t3++) {
        for (int t4 = 0; t4 < 64; t4++) {
            uint64_t u = 0;
            u += t1;
            u <<= 6;
            u += t2;
            u <<= 6;
            u += t3;
            u <<= 6;
            u += t4;
            u <<= 6;
            u += t5;
            u <<= 6;
            u ^= st[i] ^ 1763;
            std::string s = "";
            for (int i = 0; i < 7; i++) {
                s = A[(int)((u%26)&0xffffffff)] + s;
                u /= 26;
            }
            uint32_t thisHash = caml_hash(s);
            if (thisHash == toStringHash) {
                std::string flag_part;
                flag_part += A[t1];
                flag_part += A[t2];
                flag_part += A[t3];
                flag_part += A[t4];
                flag += flag_part;
                std::cout << flag_part << std::endl;
                goto END_LOOP; // oops
            }
        }}}}
END_LOOP: continue;
    }

    std::cout << "Flag: union{" << flag << "}" << std::endl;
        
    return 0;
}
