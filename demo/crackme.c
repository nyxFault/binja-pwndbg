#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int scramble_char(unsigned char c, int idx) {
    int v = (int)c;
    v ^= (0x21 + (idx * 7));
    v = ((v << 1) | (v >> 7)) & 0xff;
    v ^= 0x5a;
    return v & 0xff;
}

static int verify_key(const char *key) {
    static const int target[] = {0x4c, 0x66, 0x5f, 0x13, 0x4d, 0x66, 0x4f, 0x68};
    size_t n = strlen(key);
    size_t i;

    if (n != sizeof(target) / sizeof(target[0])) {
        return 0;
    }

    for (i = 0; i < n; i++) {
        if (scramble_char((unsigned char)key[i], (int)i) != target[i]) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        puts("usage: crackme <key>");
        return 1;
    }

    if (verify_key(argv[1])) {
        puts("Correct key. Nice work.");
        return 0;
    }

    puts("Wrong key.");
    return 1;
}
