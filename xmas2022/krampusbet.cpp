#include <vector>
#include <utility>

std::pair <int, int> bot(int board[52]) {
    bool seen[52] = {false};
    for(int i = 0; i < 52; i++) {
        if(seen[i]) continue;
        int clen = 1;
        int j = board[i];
        while(i != j) {
            seen[j] = true;
            j = board[j];
            clen++;
            if(clen >= 26) {
                return std::make_pair(i, j);
            }
        }
    }
    return std::make_pair(0, 0);
}

int tob(int to_find, int revealed_cards[52]) {
    // return first idx where not revealed
    while(revealed_cards[to_find] != -1) {
        to_find = revealed_cards[to_find];
    }
    return to_find;
}
