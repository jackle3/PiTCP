#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libunix.h"

// Given <size>, rounds it up to the next multiple of 4
unsigned round_up(unsigned size) {
    return (size + 0b11) & ~0b11;
}

void *read_file(unsigned *size, const char *name) {
    // get file size
    struct stat st;
    if (stat(name, &st) == -1) {
        sys_die(stat, "stat failed for file: %s", name);
    }
    // round up to the next multiple of four
    unsigned f_sz = st.st_size;
    *size = f_sz;

    unsigned rounded_sz = round_up(st.st_size);
    char *buf = calloc(rounded_sz, 1);
    if (!buf) {
        sys_die(buf, "calloc failed to allocate %d bytes", rounded_sz);
    }

    // open the file and read all its contents
    int fd;
    if ((fd = open(name, O_RDONLY)) == -1) {
        sys_die(open, "failed to open file: %s", name);
    }
    if (read(fd, buf, f_sz) == -1) {
        sys_die(read, "failed to read file %s", name);
    }
    
    // close the fd
    close(fd);
    return buf;
}
