# Krampus' Inferno (programming 435)

The challenge is the question described here: https://www.youtube.com/watch?v=as7Gkm7Y7h4. I used the solution as described in the video. Luckily I remembered that I had seen it before...

## Solution
```cpp
std::pair <int, int> bot666013(uint8_t board[8][8], std::pair <int, int> magic_coin) {
    uint8_t parity = 0;
    for(uint8_t i = 0; i < 8; ++i) {
        for(uint8_t j = 0; j < 8; ++j) {
            uint8_t pos = i*8+j;
            if(pos & 1 && board[i][j]) parity ^= 1;
            if(pos & 2 && board[i][j]) parity ^= 2;
            if(pos & 4 && board[i][j]) parity ^= 4;
            if(pos & 8 && board[i][j]) parity ^= 8;
            if(pos & 16 && board[i][j]) parity ^= 16;
            if(pos & 32 && board[i][j]) parity ^= 32;
        }
    }
    int target = parity ^ (magic_coin.first * 8 + magic_coin.second);
    return std::make_pair(target/8, target%8);
}
std::pair <int, int> bot1000000007(uint8_t board[8][8]) {
    uint8_t parity = 0;
    for(uint8_t i = 0; i < 8; ++i) {
        for(uint8_t j = 0; j < 8; ++j) {
            uint8_t pos = i*8+j;
            if(pos & 1 && board[i][j]) parity ^= 1;
            if(pos & 2 && board[i][j]) parity ^= 2;
            if(pos & 4 && board[i][j]) parity ^= 4;
            if(pos & 8 && board[i][j]) parity ^= 8;
            if(pos & 16 && board[i][j]) parity ^= 16;
            if(pos & 32 && board[i][j]) parity ^= 32;
        }
    }
    return std::make_pair(parity/8, parity%8);
}
// X-MAS{B07_t34mw0rk_d3f3475_Kr4mpu5}
```

I did not test the code but it worked first try. Amazing.
