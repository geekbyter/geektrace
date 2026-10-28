package com.geektrace.bench;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.os.Process;
import android.provider.Settings;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public final class MainActivity extends Activity {
    private static final String TAG = "GeekTraceBench";
    private static final String PREFIX = "geekbyter===> bench: ";
    private static final String TLS_PASSWORD = "changeit";
    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    private static final String[] ROOT_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/debug_ramdisk/su", "/system/bin/magisk", "/data/adb/magisk",
            "/data/adb/ksu", "/data/adb/ap", "/system/app/Superuser.apk",
            "/system/bin/frida-server", "/data/local/tmp/frida-server"
    };

    private static final String[] HOOK_MARKERS = {
            "frida", "gadget", "xposed", "magisk", "substrate", "zygisk",
            "riru", "kernelsu", "apatch"
    };

    private static final String[] SUSPICIOUS_PACKAGES = {
            "magisk", "kernelsu", "apatch", "supersu", "superuser",
            "xposed", "lsposed", "substrate", "frida", "riru", "zygisk"
    };

    private Button runButton;
    private TextView logView;
    private volatile boolean running;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        Log.i(TAG, PREFIX + "onCreate pid=" + Process.myPid() + " uid=" + Process.myUid()
                + " sdk=" + Build.VERSION.SDK_INT);
        runWorkload();
    }

    private void buildUi() {
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("GeekTrace Bench");
        title.setTextSize(22);
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText("External-trace workload: launch chain, detection checks, native branches, "
                + "files, crypto vectors, TLS loopback.");
        hint.setTextSize(12);
        hint.setPadding(0, pad / 2, 0, pad / 2);
        root.addView(hint);

        runButton = new Button(this);
        runButton.setText("Run bench");
        runButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                runWorkload();
            }
        });
        root.addView(runButton);

        logView = new TextView(this);
        logView.setTextSize(11);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setGravity(Gravity.TOP | Gravity.START);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(logView);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        params.topMargin = pad / 2;
        root.addView(scroll, params);
        setContentView(root);
    }

    private void runWorkload() {
        synchronized (this) {
            if (running) {
                return;
            }
            running = true;
        }
        runButton.setEnabled(false);
        logView.setText("");
        logLine("workload start vm=" + System.getProperty("java.vm.version")
                + " runtime=" + System.getProperty("java.runtime.version"));

        Thread worker = new Thread(new Runnable() {
            @Override
            public void run() {
                long start = System.nanoTime();
                try {
                    runSecurityChecks();
                    runNativeChecks();
                    runFileChecks();
                    runCryptoChecks();
                    runTlsLoopback();
                } catch (Throwable t) {
                    logLine("workload error=" + t);
                } finally {
                    long elapsedMs = (System.nanoTime() - start) / 1000000L;
                    logLine("workload done elapsed_ms=" + elapsedMs);
                    running = false;
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            runButton.setEnabled(true);
                        }
                    });
                }
            }
        }, "bench-workload");
        worker.start();
    }

    private void logLine(String message) {
        Log.i(TAG, PREFIX + message);
        final String line = message + "\n";
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (logView != null) {
                    logView.append(line);
                }
            }
        });
    }

    private void runSecurityChecks() {
        logLine("security begin");
        int probes = 0;
        for (String path : ROOT_PATHS) {
            File probe = new File(path);
            try (FileInputStream in = new FileInputStream(probe)) {
                probes++;
                logLine("security root-path readable=" + path);
            } catch (IOException e) {
                if (probe.exists()) {
                    probes++;
                    logLine("security root-path exists=" + path);
                }
            }
        }
        logLine("security root-path hits=" + probes + "/" + ROOT_PATHS.length);

        String tracerPid = "unknown";
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream("/proc/self/status"), StandardCharsets.US_ASCII))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    tracerPid = line.substring("TracerPid:".length()).trim();
                    break;
                }
            }
        } catch (IOException e) {
            logLine("security tracer-pid error=" + e);
        }
        logLine("security tracer-pid=" + tracerPid
                + ("0".equals(tracerPid) ? " clean" : " traced"));

        logLine("security debugger connected=" + Debug.isDebuggerConnected()
                + " waiting=" + Debug.waitingForDebugger());

        try {
            int adb = Settings.Global.getInt(
                    getContentResolver(), Settings.Global.ADB_ENABLED, -1);
            int development = Settings.Global.getInt(
                    getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1);
            logLine("security settings adb=" + adb + " development=" + development);
        } catch (Throwable t) {
            logLine("security settings error=" + t);
        }

        boolean debuggable = (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        logLine("security build tags=" + Build.TAGS + " type=" + Build.TYPE
                + " debuggable=" + debuggable
                + " test-keys=" + Build.FINGERPRINT.contains("test-keys"));

        try {
            List<PackageInfo> packages = getPackageManager().getInstalledPackages(0);
            List<String> suspicious = new ArrayList<>();
            if (packages != null) {
                for (PackageInfo info : packages) {
                    String name = info.packageName == null
                            ? "" : info.packageName.toLowerCase(Locale.US);
                    for (String marker : SUSPICIOUS_PACKAGES) {
                        if (name.contains(marker)) {
                            suspicious.add(info.packageName);
                            break;
                        }
                    }
                }
                logLine("security installed-apps count=" + packages.size()
                        + " suspicious=" + suspicious);
            }
        } catch (Throwable t) {
            logLine("security installed-apps error=" + t);
        }

        scanMaps();
        logLine("security PATH=" + System.getenv("PATH"));
        logLine("security done");
    }

    private void scanMaps() {
        int lines = 0;
        List<String> matches = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream("/proc/self/maps"), StandardCharsets.US_ASCII))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines++;
                String lower = line.toLowerCase(Locale.US);
                for (String marker : HOOK_MARKERS) {
                    if (lower.contains(marker) && !matches.contains(marker)) {
                        matches.add(marker);
                    }
                }
            }
        } catch (IOException e) {
            logLine("security maps error=" + e);
            return;
        }
        logLine("security maps lines=" + lines + " markers=" + matches);
    }

    private void runNativeChecks() {
        logLine("native begin");
        try {
            int[] expected = {
                    1515236178, 1515059229, 1515670226, 1515096355,
                    2397044, 4302469, 3011152, 5323407
            };
            int controlFailures = 0;
            for (int seed = 0; seed < expected.length; seed++) {
                int result = BenchNative.controlFlow(seed);
                boolean ok = result == expected[seed];
                logLine("native control-flow seed=" + seed + " result=" + result
                        + " expected=" + expected[seed] + (ok ? " PASS" : " FAIL"));
                if (!ok) {
                    controlFailures++;
                }
            }
            logLine("native control-flow done failures=" + controlFailures);

            byte[] data = "geektrace-bench".getBytes(StandardCharsets.US_ASCII);
            long hash = BenchNative.fnv1a(data);
            logLine("native fnv1a len=" + data.length
                    + " value=" + Long.toUnsignedString(hash)
                    + " hex=" + String.format(Locale.US, "%016x", hash)
                    + " expected=978154e456c326bd");

            int fd = BenchNative.memfdDex();
            logLine("native memfd-dex fd=" + fd);
            if (fd >= 0) {
                BenchNative.closeFd(fd);
            }
        } catch (Throwable t) {
            logLine("native error=" + t);
        }
        logLine("native done");
    }

    private void runFileChecks() {
        logLine("file begin");
        try {
            File token = new File(getFilesDir(), "token.bin");
            byte[] payload = "geektrace-bench-token-v1".getBytes(StandardCharsets.US_ASCII);
            try (FileOutputStream out = new FileOutputStream(token)) {
                out.write(payload);
            }
            byte[] readBack = readAll(token);
            logLine("file token path=" + token.getAbsolutePath()
                    + " bytes=" + readBack.length
                    + " sha256=" + hex(digestBytes("SHA-256", readBack))
                    + " expected=86672da495693335daabfe27441a779e83e37b79afe98cf2e0c0e45f29013bc1");

            File staged = new File(getCacheDir(), "stage.bin");
            File renamed = new File(getCacheDir(), "final.bin");
            try (FileOutputStream out = new FileOutputStream(staged)) {
                out.write("geektrace-bench-payload-v1".getBytes(StandardCharsets.US_ASCII));
            }
            boolean moved = staged.renameTo(renamed);
            byte[] cacheBytes = readAll(renamed);
            logLine("file cache move=" + moved + " path=" + renamed.getAbsolutePath()
                    + " bytes=" + cacheBytes.length
                    + " sha256=" + hex(digestBytes("SHA-256", cacheBytes)));
        } catch (Throwable t) {
            logLine("file error=" + t);
        }
        logLine("file dirs files=" + getFilesDir().getAbsolutePath()
                + " cache=" + getCacheDir().getAbsolutePath());
        logLine("file done");
    }

    private void runCryptoChecks() {
        logLine("crypto begin");
        int failures = 0;
        failures += cryptoAesCbc();
        failures += cryptoAesGcm();
        failures += cryptoDes();
        failures += cryptoDigests();
        failures += cryptoHmac();
        failures += cryptoRsa();
        failures += cryptoEcdsa();
        logLine("crypto done failures=" + failures);
    }

    private int cryptoAesCbc() {
        try {
            byte[] key = hex("2b7e151628aed2a6abf7158809cf4f3c");
            byte[] iv = hex("000102030405060708090a0b0c0d0e0f");
            byte[] plain = hex("6bc1bee22e409f96e93d7e117393172a");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(plain);
            int failures = check("aes-cbc-128-encrypt", encrypted,
                    "7649abac8119b246cee98e9b12e9197d");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
            failures += checkBytes("aes-cbc-128-decrypt", cipher.doFinal(encrypted), plain);
            return failures;
        } catch (Throwable t) {
            logLine("crypto aes-cbc error=" + t);
            return 1;
        }
    }

    private int cryptoAesGcm() {
        try {
            byte[] key = new byte[16];
            byte[] iv = new byte[12];
            byte[] plain = new byte[16];
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
            byte[] encrypted = cipher.doFinal(plain);
            int failures = check("aes-gcm-128-ciphertext",
                    Arrays.copyOfRange(encrypted, 0, 16),
                    "0388dace60b6a392f328c2b971b2fe78");
            failures += check("aes-gcm-128-tag",
                    Arrays.copyOfRange(encrypted, 16, 32),
                    "ab6e47d42cec13bdf53a67b21257bddf");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
            failures += checkBytes("aes-gcm-128-decrypt",
                    cipher.doFinal(encrypted), plain);
            return failures;
        } catch (Throwable t) {
            logLine("crypto aes-gcm error=" + t);
            return 1;
        }
    }

    private int cryptoDes() {
        try {
            byte[] key = hex("133457799BBCDFF1");
            byte[] plain = hex("0123456789ABCDEF");
            SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(plain);
            int failures = check("des-ecb-encrypt", encrypted, "85e813540f0ab405");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            failures += checkBytes("des-ecb-decrypt", cipher.doFinal(encrypted), plain);
            return failures;
        } catch (Throwable t) {
            logLine("crypto des error=" + t);
            return 1;
        }
    }

    private int cryptoDigests() {
        int failures = 0;
        try {
            failures += digestCheck("sha1-abc", "SHA-1",
                    "a9993e364706816aba3e25717850c26c9cd0d89d");
            failures += digestCheck("sha256-abc", "SHA-256",
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            failures += digestCheck("md5-abc", "MD5",
                    "900150983cd24fb0d6963f7d28e17f72");
            try {
                failures += digestCheck("md4-abc", "MD4",
                        "a448017aaf21d8525fc10ae87aa6729d");
            } catch (NoSuchAlgorithmException e) {
                logLine("crypto md4 unavailable (stock Android has no MD4 provider)");
            }
        } catch (Throwable t) {
            failures++;
            logLine("crypto digest error=" + t);
        }
        return failures;
    }

    private int digestCheck(String label, String algorithm, String expected) throws Exception {
        byte[] digest = digestBytes(algorithm, "abc".getBytes(StandardCharsets.US_ASCII));
        return check(label, digest, expected);
    }

    private int cryptoHmac() {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec("key".getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
            byte[] value = mac.doFinal(
                    "The quick brown fox jumps over the lazy dog"
                            .getBytes(StandardCharsets.US_ASCII));
            return check("hmac-sha256", value,
                    "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
        } catch (Throwable t) {
            logLine("crypto hmac error=" + t);
            return 1;
        }
    }

    private int cryptoRsa() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            byte[] message = "geektrace-bench-payload-v1".getBytes(StandardCharsets.US_ASCII);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
            byte[] encrypted = cipher.doFinal(message);
            cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
            byte[] decrypted = cipher.doFinal(encrypted);

            int failures = checkBytes("rsa-2048-oaep-roundtrip", decrypted, message);
            logLine("crypto rsa-2048-oaep ciphertext_bytes=" + encrypted.length);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(pair.getPrivate());
            signature.update(message);
            byte[] sig = signature.sign();
            signature.initVerify(pair.getPublic());
            signature.update(message);
            boolean verified = signature.verify(sig);
            logLine("crypto rsa-2048-sha256-signature bytes=" + sig.length
                    + " verify=" + verified);
            if (!verified) {
                failures++;
            }
            return failures;
        } catch (Throwable t) {
            logLine("crypto rsa error=" + t);
            return 1;
        }
    }

    private int cryptoEcdsa() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            byte[] message = "geektrace-bench-payload-v1".getBytes(StandardCharsets.US_ASCII);

            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(pair.getPrivate());
            signature.update(message);
            byte[] sig = signature.sign();
            signature.initVerify(pair.getPublic());
            signature.update(message);
            boolean verified = signature.verify(sig);
            logLine("crypto ecdsa-p256-sha256-signature bytes=" + sig.length
                    + " verify=" + verified);
            return verified ? 0 : 1;
        } catch (Throwable t) {
            logLine("crypto ecdsa error=" + t);
            return 1;
        }
    }

    private void runTlsLoopback() {
        logLine("tls loopback begin");
        SSLServerSocket server = null;
        Thread serverThread = null;
        final String[] serverResult = new String[2];
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = getAssets().open("bench-tls.p12")) {
                keyStore.load(in, TLS_PASSWORD.toCharArray());
            }
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keyStore, TLS_PASSWORD.toCharArray());

            SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(keyManagers.getKeyManagers(), null, null);
            server = (SSLServerSocket) serverContext.getServerSocketFactory()
                    .createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
            server.setSoTimeout(8000);
            final int port = server.getLocalPort();
            final SSLServerSocket boundServer = server;

            serverThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    try (SSLSocket socket = (SSLSocket) boundServer.accept()) {
                        socket.setSoTimeout(8000);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(
                                socket.getInputStream(), StandardCharsets.US_ASCII));
                        String requestLine = reader.readLine();
                        String line;
                        while ((line = reader.readLine()) != null && !line.isEmpty()) {
                            // drain request headers
                        }
                        byte[] body = "geektrace-bench-ok\n".getBytes(StandardCharsets.US_ASCII);
                        String header = "HTTP/1.1 200 OK\r\n"
                                + "Content-Type: text/plain\r\n"
                                + "Content-Length: " + body.length + "\r\n"
                                + "Connection: close\r\n\r\n";
                        OutputStream out = socket.getOutputStream();
                        out.write(header.getBytes(StandardCharsets.US_ASCII));
                        out.write(body);
                        out.flush();
                        serverResult[0] = requestLine;
                    } catch (Throwable t) {
                        serverResult[1] = t.toString();
                    }
                }
            }, "bench-tls-server");
            serverThread.start();

            TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }};
            SSLContext clientContext = SSLContext.getInstance("TLS");
            clientContext.init(null, trustAll, new SecureRandom());

            try (SSLSocket client = (SSLSocket) clientContext.getSocketFactory()
                    .createSocket("127.0.0.1", port)) {
                client.setSoTimeout(8000);
                client.startHandshake();
                String protocol = client.getSession().getProtocol();
                String suite = client.getSession().getCipherSuite();
                OutputStream out = client.getOutputStream();
                out.write(("GET /bench HTTP/1.1\r\n"
                        + "Host: 127.0.0.1\r\n"
                        + "Connection: close\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                out.flush();
                BufferedReader reader = new BufferedReader(new InputStreamReader(
                        client.getInputStream(), StandardCharsets.US_ASCII));
                String status = reader.readLine();
                String line;
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    // drain response headers
                }
                StringBuilder body = new StringBuilder();
                int ch;
                while ((ch = reader.read()) != -1) {
                    body.append((char) ch);
                }
                logLine("tls loopback protocol=" + protocol + " cipher=" + suite
                        + " status=" + status + " body=" + body.toString().trim());
            }

        } catch (Throwable t) {
            logLine("tls loopback error=" + t);
        } finally {
            if (server != null) {
                try {
                    server.close();
                } catch (IOException ignored) {
                }
            }
            if (serverThread != null) {
                try {
                    serverThread.join(3000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
                if (serverThread.isAlive()) {
                    logLine("tls server join timeout");
                }
            }
            if (serverResult[0] != null) {
                logLine("tls server request-line=" + serverResult[0]);
            }
            if (serverResult[1] != null) {
                logLine("tls server error=" + serverResult[1]);
            }
        }
        logLine("tls done");
    }

    private static byte[] readAll(File file) throws IOException {
        try (InputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static byte[] digestBytes(String algorithm, byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest.digest(data);
    }

    private static int check(String label, byte[] actual, String expectedHex) {
        String got = hex(actual);
        boolean ok = got.equalsIgnoreCase(expectedHex);
        Log.i(TAG, PREFIX + "crypto " + label + (ok ? " PASS" : " FAIL")
                + " got=" + got + " expected=" + expectedHex);
        return ok ? 0 : 1;
    }

    private static int checkBytes(String label, byte[] actual, byte[] expected) {
        boolean ok = Arrays.equals(actual, expected);
        Log.i(TAG, PREFIX + "crypto " + label + (ok ? " PASS" : " FAIL")
                + " bytes=" + actual.length);
        return ok ? 0 : 1;
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] value) {
        StringBuilder out = new StringBuilder(value.length * 2);
        for (byte b : value) {
            out.append(HEX_DIGITS[(b >> 4) & 0x0f]);
            out.append(HEX_DIGITS[b & 0x0f]);
        }
        return out.toString();
    }
}
