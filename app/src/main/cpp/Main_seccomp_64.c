/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <jni.h>
#include <android/log.h>
#include <assert.h>
#include "bypass_dlfcn.h"
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <asm-generic/unistd.h>
#include "const.h"
#include "linux_syscall_support.h"
#include <stddef.h>
#include <stddef.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/elf.h>
#include "seccommp.h"

#if defined(__aarch64__)

static const char* kTAG = "darren-jni";
#define LOGI(...) \
  ((void)__android_log_print(ANDROID_LOG_INFO, kTAG, __VA_ARGS__))
#define LOGW(...) \
  ((void)__android_log_print(ANDROID_LOG_WARN, kTAG, __VA_ARGS__))
#define LOGE(...) \
  ((void)__android_log_print(ANDROID_LOG_ERROR, kTAG, __VA_ARGS__))

struct sock_filter filter2[] = {

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECMAGIC, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP)
};


#define SECMAGIC 0xdeadbeef
void sig_handler(int signo, siginfo_t *info, void *data) {

    int my_signo = info->si_signo;
    LOGE("sig_handler2, my_signo: %x, signo:%d \n", my_signo, signo);
    unsigned long sysno = ((ucontext_t *) data)->uc_mcontext.regs[8];
    LOGE("sig_handler2, sysno: %d\n", sysno);
    switch (sysno) {
        case __NR_openat: {
            unsigned long arg0 = ((ucontext_t *) data)->uc_mcontext.regs[0];
            LOGE("sig_handler2, regs[0]: %x\n", arg0);
            unsigned long arg1 = ((ucontext_t *) data)->uc_mcontext.regs[1];
            LOGE("sig_handler2, regs[1]: %s\n", arg1);
            unsigned long arg2 = ((ucontext_t *) data)->uc_mcontext.regs[2];
            LOGE("sig_handler2, regs[2]: %d\n", arg2);
            unsigned long arg3 = ((ucontext_t *) data)->uc_mcontext.regs[3];
            LOGE("sig_handler2, regs[3]: %d\n", arg3);
            int open_fd = 0;
            open_fd = syscall(__NR_openat, arg0, arg1, arg2, arg3,SECMAGIC);
            LOGE("[__NR_openat]fd: %ld\n", open_fd);
            if (open_fd < 0) {
                LOGE("[__NR_openat]error: %ld, %s\n", errno, strerror(errno));
            }
            ((ucontext_t *) data)->uc_mcontext.regs[0] = open_fd;
        }break;
        default:
            break;
    }
}



int arm64_jni_test(JNIEnv* env, jobject thiz){


    LOGE("sigaction init 1.\n");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        LOGE("prctl(PR_SET_NO_NEW_PRIVS)");
        return 1;
    }
    LOGE("sigaction init 2.\n");
    struct sock_fprog prog;
    prog.filter = filter2;
    prog.len = (unsigned short) (sizeof(filter2) / sizeof(filter2[0]));
    LOGE("sigaction init 3.\n");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        LOGE("prctl(PR_SET_NO_NEW_PRIVS)");
        return 1;
    }
    LOGE("sigaction init 4.\n");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        LOGE("when setting seccomp filter");
        return 1;
    }
    LOGE("sigaction init 5.\n");

    struct sigaction sa;
    sigset_t sigset;
    sigfillset(&sigset);

    LOGE("sigaction init 6.\n");

    sa.sa_sigaction = sig_handler;
    sa.sa_mask = sigset;
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSYS, &sa, NULL) == -1) {
        LOGE("sigaction init failed.\n");
        return 1;
    }
    LOGE("sigaction init 7.\n");
    int ret = scan_maps();
    LOGE("sigaction init 8.==%ld\n", ret);

    return 0;
}


#endif  //#if defined(__aarch64__)