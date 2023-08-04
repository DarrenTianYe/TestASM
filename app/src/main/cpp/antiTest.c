//
// Created by darren on 2022/12/7.
//
#include <jni.h>
#include <stdlib.h>
#include <pty.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "logging.h"
#include "linux_syscall_support.h"

 int scan_maps() {
    FILE *fp = NULL;
    char line[PATH_MAX];
    char maps[] = "/proc/self/maps";
    int fd = sys_open(maps, O_RDONLY, 0);
    if (fd < 0) {
        LOGE("cannot sys_open>>>> %s, %d, %s", maps, errno, strerror(errno));
        return -1;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        LOGE("cannot fopen>>>> %s, %d, %s", maps, errno, strerror(errno));
        close(fd);
        return -1;
    }
    while(fgets(line, PATH_MAX - 1, fp) != NULL) {
        if (strchr(line, '/') == NULL) continue;
        if (strstr(line, " /system/") != NULL ||
            strstr(line, " /vendor/") != NULL ||
            strstr(line, " /product/") != NULL ||
            strstr(line, " /system_ext/") != NULL ||
            strstr(line, " dkplugin") != NULL){


        }
    }
    LOGE("fgets: %s", line);
    fclose(fp);
    close(fd);
    return 0;
}