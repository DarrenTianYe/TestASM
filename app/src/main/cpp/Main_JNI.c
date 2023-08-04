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
#include "seccommp.h"


static const char* kTAG = "darren-jni";
#define LOGI(...) \
  ((void)__android_log_print(ANDROID_LOG_INFO, kTAG, __VA_ARGS__))
#define LOGW(...) \
  ((void)__android_log_print(ANDROID_LOG_WARN, kTAG, __VA_ARGS__))
#define LOGE(...) \
  ((void)__android_log_print(ANDROID_LOG_ERROR, kTAG, __VA_ARGS__))


JNIEXPORT jstring JNICALL
Java_com_example_hellojnicallback_MainActivity_staticstringFromJNI( JNIEnv* env, jclass thiz )
{ //

  return (*env)->NewStringUTF(env, "Hello from JNI staticstringFromJNI  ");
}

JNIEXPORT jstring JNICALL
Java_com_example_hellojnicallback_MainActivity_stringFromJNI12( JNIEnv* env, jobject thiz )
{ //Java_com_example_myapplication_MainActivity_stringFromJNI


  LOGE("darren stringFromJNI12 :%p",thiz );

#if defined(__arm__)

  LOGE("darren __arm__ stringFromJNI12 :%s",thiz );

  arm_jni_test(env, thiz);

#endif  //#if defined(__arm__)


#if defined(__aarch64__)

  LOGE("darren __arm64__ stringFromJNI12 :%p",thiz );

  arm64_jni_test(env, thiz);

#endif  //#if defined(__aarch64__)


  return (*env)->NewStringUTF(env, "asm test");
}
