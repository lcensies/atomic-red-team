#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

static const char SYMNAME[] = "open";

extern int open(const char *pathname, int flags, mode_t mode);

int (*orig_open)(const char *, int, mode_t);

int open(const char *pathname, int flags, mode_t mode) {
    // This malloc is here to increase our chances to get properly mapped memory (from kernel point of view) to be passed to dlsym
    char *buf;
    buf = malloc(10);
    if (!buf) {
        return -1;
    }

    memcpy(buf, &SYMNAME, sizeof(SYMNAME));

    fprintf(stderr, "I am evil %s!\n", buf);

    if (!orig_open)
        orig_open = dlsym(RTLD_NEXT, buf);

    return orig_open(pathname, flags, mode);
}
