//
// Created by darren on 2022/12/7.
//

#include <jni.h>

#ifndef SECCOMP_CONST_H
#define SECCOMP_CONST_H

int arm_jni_test( JNIEnv* env, jobject thiz);
int arm64_jni_test(JNIEnv* env, jobject thiz);

#define SECMAGIC 0xdeadbeef

#endif //SECCOMP_CONST_H
