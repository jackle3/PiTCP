// engler, cs140e: your code to find the tty-usb device on your laptop.
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libunix.h"

#define _SVID_SOURCE
#include <dirent.h>
static const char *ttyusb_prefixes[] = {"ttyUSB",        // linux
                                        "ttyACM",        // linux
                                        "cu.SLAB_USB",   // mac os
                                        "cu.usbserial",  // mac os
                                        // if your system uses another name, add it.
                                        0};

static int filter(const struct dirent *d) {
    // scan through the prefixes, returning 1 when you find a match.
    // 0 if there is no match.

    // iterate through all prefixes until null
    for (const char **prefix = ttyusb_prefixes; *prefix; prefix++) {
        // check if dirent name starts with current prefix
        if (strncmp(d->d_name, *prefix, strlen(*prefix)) == 0) {
            return 1;
        }
    }
    return 0;
}

// find the TTY-usb device (if any) by using <scandir> to search for
// a device with a prefix given by <ttyusb_prefixes> in /dev
// returns:
//  - device name.
// error: panic's if 0 or more than 1 devices.
char *find_ttyusb(void) {
    // use <alphasort> in <scandir>
    // return a malloc'd name so doesn't corrupt.
    struct dirent **namelist;
    int cnt = scandir("/dev", &namelist, filter, alphasort);
    if (cnt == -1) {
        sys_die(scandir, "scandir failed to read /dev");
    } else if (cnt == 0 || cnt > 1) {
        panic("unexpected: scandir found %d TTY-usb devices", cnt);
    }
    char *path = strdupf("/dev/%s", (*namelist)->d_name);
    for (int i = 0; i < cnt; i++) free(namelist[i]);
    free(namelist);
    return path;
}

// return the most recently mounted ttyusb (the one
// mounted last).  use the modification time
// returned by state.
char *find_ttyusb_last(void) {
    // use scandir to get all matching tty devices
    struct dirent **namelist;
    int cnt = scandir("/dev", &namelist, filter, alphasort);
    if (cnt == -1)
        sys_die(scandir, "scandir failed to read /dev");
    if (cnt == 0)
        return 0;

    // find device with latest modification time
    time_t latest_mtime = 0;
    int latest_idx = -1;

    for (int i = 0; i < cnt; i++) {
        char *path = strdupf("/dev/%s", namelist[i]->d_name);
        struct stat st;
        if (stat(path, &st) < 0)
            sys_die(stat, "stat failed on %s", path);

        if (latest_idx == -1 || st.st_mtime > latest_mtime) {
            latest_mtime = st.st_mtime;
            latest_idx = i;
        }
        free(path);
    }

    // return path of latest device
    char *result = strdupf("/dev/%s", namelist[latest_idx]->d_name);

    // cleanup
    for (int i = 0; i < cnt; i++) free(namelist[i]);
    free(namelist);

    return result;
}

// return the oldest mounted ttyusb (the one mounted
// "first") --- use the modification returned by
// stat()
char *find_ttyusb_first(void) {
    // use scandir to get all matching tty devices
    struct dirent **namelist;
    int cnt = scandir("/dev", &namelist, filter, alphasort);
    if (cnt == -1)
        sys_die(scandir, "scandir failed to read /dev");
    if (cnt == 0)
        return 0;

    // find device with earliest modification time
    time_t earliest_mtime = 0;
    int earliest_idx = -1;

    for (int i = 0; i < cnt; i++) {
        char *path = strdupf("/dev/%s", namelist[i]->d_name);
        struct stat st;
        if (stat(path, &st) < 0)
            sys_die(stat, "stat failed on %s", path);

        if (earliest_idx == -1 || st.st_mtime < earliest_mtime) {
            earliest_mtime = st.st_mtime;
            earliest_idx = i;
        }
        free(path);
    }

    // return path of earliest device
    char *result = strdupf("/dev/%s", namelist[earliest_idx]->d_name);

    // cleanup
    for (int i = 0; i < cnt; i++) free(namelist[i]);
    free(namelist);

    return result;
}
