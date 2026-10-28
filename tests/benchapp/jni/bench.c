#include <jni.h>
#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1U
#endif

#define TAG "GeekTraceBench"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

__attribute__((noinline))
static int mix_affine(int value) {
    return (value * 3 + 1) & 0x7fffffff;
}

__attribute__((noinline))
static int mix_xor(int value) {
    return ((value ^ 0x5a5a5a5a) + 7) & 0x7fffffff;
}

static jint JNICALL native_controlFlow(JNIEnv *env, jclass clazz, jint seed) {
    (void)env;
    (void)clazz;
    int acc = seed;
    if (seed & 1) {
        acc += 11;
    } else {
        acc -= 7;
    }

    int i = 0;
    while (i < 5) {
        acc += i * i;
        i++;
    }

    do {
        acc ^= (acc << 3);
        acc &= 0x7fffffff;
        i--;
    } while (i > 0);

    switch (seed & 3) {
        case 0:
            acc += 100;
            break;
        case 1:
            acc += 200;
            break;
        case 2:
            acc -= 50;
            break;
        default:
            acc ^= 0x1234;
            break;
    }

    int (*fn)(int) = (seed & 4) ? mix_affine : mix_xor;
    acc = fn(acc);

    for (int j = 0; j < 4; j++) {
        if (acc & (1 << j)) {
            acc += j * 3;
        } else {
            acc -= j;
        }
    }
    acc &= 0x7fffffff;
    LOGI("geekbyter===> bench-native: control-flow seed=%d result=%d", seed, acc);
    return acc;
}

static jlong JNICALL native_fnv1a(JNIEnv *env, jclass clazz, jbyteArray data) {
    (void)clazz;
    if (data == NULL) {
        return 0;
    }
    jsize length = (*env)->GetArrayLength(env, data);
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
        return 0;
    }
    uint64_t hash = 14695981039346656037ULL;
    for (jsize i = 0; i < length; i++) {
        hash ^= (uint8_t)bytes[i];
        hash *= 1099511628211ULL;
    }
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    LOGI("geekbyter===> bench-native: fnv1a len=%d hash=%llu", length,
         (unsigned long long)hash);
    return (jlong)hash;
}

static jint JNICALL native_memfdDex(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    int fd = (int)syscall(__NR_memfd_create, "bench-dex", MFD_CLOEXEC);
    if (fd < 0) {
        LOGI("geekbyter===> bench-native: memfd_create failed errno=%d", errno);
        return -1;
    }
    const char dex_magic[] = "dex\n035";
    ssize_t written = write(fd, dex_magic, sizeof(dex_magic) - 1);
    lseek(fd, 0, SEEK_SET);
    LOGI("geekbyter===> bench-native: memfd dex fd=%d bytes=%zd", fd, written);
    return fd;
}

static void JNICALL native_closeFd(JNIEnv *env, jclass clazz, jint fd) {
    (void)env;
    (void)clazz;
    if (fd >= 0) {
        close(fd);
    }
}

static JNINativeMethod methods[] = {
    {"controlFlow", "(I)I", (void *)native_controlFlow},
    {"fnv1a", "([B)J", (void *)native_fnv1a},
    {"memfdDex", "()I", (void *)native_memfdDex},
    {"closeFd", "(I)V", (void *)native_closeFd},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass clazz = (*env)->FindClass(env, "com/geektrace/bench/BenchNative");
    if (clazz == NULL) {
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, clazz, methods,
                                sizeof(methods) / sizeof(methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    (*env)->DeleteLocalRef(env, clazz);
    LOGI("geekbyter===> bench-native: JNI_OnLoad registered %zu methods",
         sizeof(methods) / sizeof(methods[0]));
    return JNI_VERSION_1_6;
}
