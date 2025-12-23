// File: app/src/main/java/com/example/securechat/RootDetection.java
package com.example.securechat;

import android.os.Build;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import android.content.Context;

public class RootDetection {

    /**
     * Check if device is rooted
     * @return true if rooted, false otherwise
     */
    public static boolean isDeviceRooted(Context context) {
        return checkRootMethod1() || checkRootMethod2() || checkRootMethod3() || checkRootMethod4()
                || checkRootMethod6()
                || checkRootMethod7();
    }

    /**
     * Method 1: Check for SU binary
     */
    private static boolean checkRootMethod1() {
        String[] paths = {
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/su/bin/su"
        };

        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Method 2: Check for dangerous apps
     */
    private static boolean checkRootMethod2() {
        String[] packages = {
                "com.noshufou.android.su",
                "com.noshufou.android.su.elite",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.thirdparty.superuser",
                "com.yellowes.su",
                "com.topjohnwu.magisk",
                "com.kingroot.kinguser",
                "com.kingo.root",
                "com.smedialink.oneclickroot",
                "com.zhiqupk.root.global",
                "com.alephzain.framaroot"
        };

        for (String packageName : packages) {
            try {
                // Try to find package
                Class.forName("android.content.pm.PackageManager")
                        .getMethod("getPackageInfo", String.class, int.class)
                        .invoke(null, packageName, 0);
                return true;
            } catch (Exception ignored) {
                // Package not found, continue
            }
        }
        return false;
    }

    /**
     * Method 3: Check build tags for test-keys
     */
    private static boolean checkRootMethod3() {
        String buildTags = Build.TAGS;
        return buildTags != null && buildTags.contains("test-keys");
    }

    /**
     * Method 4: Try executing SU command
     */
    private static boolean checkRootMethod4() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[] { "/system/xbin/which", "su" });
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return in.readLine() != null;
        } catch (Throwable t) {
            return false;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    /**
     * Method 6: Check if /system is writable
     */
    private static boolean checkRootMethod6() {
        try {
            Process process = Runtime.getRuntime().exec("mount");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) {
                if (line.contains(" /system ") || line.contains(" /vendor ")) {
                    if (line.contains("rw")) {
                        return true;
                    }
                }
            }
            in.close();
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * Method 7: Check running processes for root daemons
     */
    private static boolean checkRootMethod7() {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) {
                if (line.contains("magisk") || line.contains("su") || line.contains("daemon")) {
                    return true;
                }
            }
            in.close();
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * Get root detection details (for logging)
     */
    public static String getRootDetectionDetails() {
        StringBuilder details = new StringBuilder();
        details.append("Root Detection Results:\n");
        details.append("- SU Binary Check: ").append(checkRootMethod1()).append("\n");
        details.append("- Dangerous Apps Check: ").append(checkRootMethod2()).append("\n");
        details.append("- Build Tags Check: ").append(checkRootMethod3()).append("\n");
        details.append("- SU Command Check: ").append(checkRootMethod4()).append("\n");
        details.append("- Build Tags: ").append(Build.TAGS).append("\n");
        return details.toString();
    }
}