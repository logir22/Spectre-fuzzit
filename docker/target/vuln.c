/* SPECTRE demo target: intentionally vulnerable C.
 *
 * Exercises all three analysis stages:
 *   - Static taint (Semgrep / Joern): `read` writes into `data`, which flows
 *     into `memcpy` in the SAME function (so intra-procedural taint fires).
 *   - Fuzzing (AFL++ + ASAN): the first stdin byte is the length; a value
 *     > 32 triggers a stack buffer overflow in memcpy.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    /* Path 1: command-line argument -> memcpy (Semgrep flags the sink). */
    if (argc > 1) {
        char buf[32];
        memcpy(buf, argv[1], strlen(argv[1]));
        buf[31] = '\0';
        printf("%s\n", buf);
        return 0;
    }

    /* Path 2: stdin -> memcpy (Joern taint + AFL++ crash). */
    unsigned char len = 0;
    if (read(STDIN_FILENO, &len, 1) != 1) {
        return 0;
    }

    char data[64];
    ssize_t n = read(STDIN_FILENO, data, len);
    if (n > 0) {
        char buf[32];
        memcpy(buf, data, n); /* len > 32 => ASAN stack-buffer-overflow */
        buf[31] = '\0';
        printf("%s\n", buf);
    }
    return 0;
}
