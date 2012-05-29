#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "util.h"
#include "xtea.h"

#define MAX_CMD_SIZE    1024    /*put in hdr */
#define REDIRECT_DEVNULL    13 /* "&> /dev/null" is concatenated on other end */
#define KEY "a1487b33FcAc3FD8aa9D4d44e4e402AFDa955cc514cEC0368bB8eD717aaa8cC5\0" 
#define CHARS_ENCODED   sizeof(uint32_t) / sizeof(char) * 2
#define KEY0    0x57178863
#define KEY1    0x0c41555d
#define KEY2    0xfa2044d9
#define KEY3    0x8dff3784

int encrypt_command(const char *cmd)
{
    char command[MAX_CMD_SIZE];
    size_t len;
    size_t padding;
    size_t i;
    uint32_t const key[4] = { KEY0, KEY1, KEY2, KEY3 };

    if (strlen(cmd) >= MAX_CMD_SIZE - REDIRECT_DEVNULL)
    {
        fprintf(stderr, "<msg> can only be %d characters long\n", 
                MAX_CMD_SIZE - REDIRECT_DEVNULL);
        return -1;
    }
    memset(command, 0, MAX_CMD_SIZE);
    strcpy(command, cmd);

    len = strlen(command);
    padding = CHARS_ENCODED - strlen(command) % (CHARS_ENCODED);

    for (i = 0; i < len; i += CHARS_ENCODED)
    {
        encipher(RCM_NUM_ROUNDS, (uint32_t *) &command[i], key);
    }

    for (i = 0; i < len + padding; i++)
    {
        printf("%c", command[i]);
    }
    return 0;
}

int b2l_endian(const char *intarg, const char *bin)
{
    uint16_t input;

    if (!(input = strtol(intarg, NULL, 10)))
    {
        fprintf(stderr, "usage: %s [ -e COMMAND | -b INT ]\n", bin);
        return -1;
    }
    printf("%d", htons(input));
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        printf("%d", port_from_date());
        return 0;
    }
    if (argc > 2)
    {
        if (!strcmp(argv[1], "-e"))
        {
            return encrypt_command(argv[2]);
        }
        if (!strcmp(argv[1], "-b"))
        {
            return b2l_endian(argv[2], argv[0]);
        }
    }
    fprintf(stderr, "usage: %s [ -e COMMAND | -b INT ]\n", argv[0]);
    return 1;
}
