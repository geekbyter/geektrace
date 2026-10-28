package com.geektrace.bench;

public final class BenchNative {
    static {
        System.loadLibrary("bench");
    }

    private BenchNative() {
    }

    public static native int controlFlow(int seed);

    public static native long fnv1a(byte[] data);

    public static native int memfdDex();

    public static native void closeFd(int fd);
}
