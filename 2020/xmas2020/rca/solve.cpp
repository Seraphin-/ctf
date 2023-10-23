#include <bitset>
#include <iostream>
#include <string>

std::bitset<70> matrix[70];

inline bool getCell(int x, int y) {
    if(x < 0) x = 69;
    if(x >= 70) x = 0;
    if(y < 0) y = 69;
    if(y >= 70) y = 0;
    return matrix[y][x];
}

inline void putCell(int x, int y, bool value) {
    if(x < 0) x = 69;
    if(x >= 70) x = 0;
    if(y < 0) y = 69;
    if(y >= 70) y = 0;
    matrix[y][x] = value;
}

inline std::bitset<4> getSquare(int x, int y) {
    std::bitset<4> temp;
    temp[0] = getCell(x, y);
    temp[1] = getCell(x+1, y);
    temp[2] = getCell(x, y+1);
    temp[3] = getCell(x+1, y+1);
    return temp;
}

inline void putSquare(int x, int y, std::bitset<4> &square) {
    putCell(x, y, square[0]);
    putCell(x+1, y, square[1]);
    putCell(x, y+1, square[2]);
    putCell(x+1, y+1, square[3]);
}

void processSquare(int x, int y) {
    std::bitset<4> square = getSquare(x, y);
    // std::cout << square << std::endl;
    size_t count = square.count();
    if(count == 1) {
        bool t = square[0];
        square[0] = square[3];
        square[3] = t;
        t = square[1];
        square[1] = square[2];
        square[2] = t;
    }
    if(count != 2) square.flip();
    // std::cout << square << std::endl;
    putSquare(x, y, square);
}

void prevMatrix(int startCoord) {
    for(int i = startCoord; i < 70; i += 2)
        for(int j = startCoord; j < 70; j += 2)
            processSquare(i, j);
}

int main() {
#include "matrix.cc"
    for(int i = 160760160; i > 160760000; --i) {
        /** Was using this when I thought I needed to go all the way back
        if(i % 10000000 == 0) {
            std::cout << i << "\n====================\n";
            for(auto r : matrix) {
                std::cout << r.to_string() << std::endl;
            }
            std::cout << "\n====================\n";

        }*/
        prevMatrix(-(i % 2));
    }

    // Print the final one
    std::cout << "The final state is..." << std::endl;
    std::cout << "╔══════════════════════════════════════════════════════════════════════╗" << std::endl;
    for(auto r : matrix) {
        std::cout << "║";
        for(char v : r.to_string()) {
            if(v == '1') std::cout << "█";
            else std::cout << " ";
        }
        std::cout << "║" << std::endl;
    }
    std::cout << "╚══════════════════════════════════════════════════════════════════════╝ " << std::endl;

    return 0;
}
