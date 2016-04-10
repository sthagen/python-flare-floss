#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "base64.h"


int decode(void *out, size_t out_len, const void *in, size_t in_len) {
    return Base64decode(out, in) == in_len;
}

char in[] = "aGVsbG8gd29ybGQ=";

int main(int argc, char **argv) {
    char out[sizeof(in) + 1];

    if (decode(out, sizeof(in) + 1, in, sizeof(in))) {
        perror("failed to decode.\n");
        return -1;
    }
    printf("%s\n", out);
    return 0;
}
