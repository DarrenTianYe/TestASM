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
#include "const.h"


// Android log function wrappers
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
#if defined(__arm__)
    #if defined(__ARM_ARCH_7A__)
    #if defined(__ARM_NEON__)
      #if defined(__ARM_PCS_VFP)
        #define ABI "armeabi-v7a/NEON (hard-float)"
      #else
        #define ABI "armeabi-v7a/NEON"
      #endif
    #else
      #if defined(__ARM_PCS_VFP)
        #define ABI "armeabi-v7a (hard-float)"
      #else
        #define ABI "armeabi-v7a"
      #endif
    #endif
  #else
   #define ABI "armeabi"
  #endif
#elif defined(__i386__)
#define ABI "x86"
#elif defined(__x86_64__)
#define ABI "x86_64"
#elif defined(__mips64)  /* mips64el-* toolchain defines __mips__ too */
#define ABI "mips64"
#elif defined(__mips__)
#define ABI "mips"
#elif defined(__aarch64__)
#define ABI "arm64-v8a"
#else
#define ABI "unknown"
#endif

    scan_maps();
//    void *handle = bp_dlopen("libart.so", RTLD_NOW);
//    void *pretty_method = bp_dlsym(handle, "_ZN3art9ArtMethod12PrettyMethodEb");
//    LOGE(" bypass dlopen, dlopen result: %p,  pretty_method result: %p", handle, pretty_method);

    return (*env)->NewStringUTF(env, "asm test");
}
