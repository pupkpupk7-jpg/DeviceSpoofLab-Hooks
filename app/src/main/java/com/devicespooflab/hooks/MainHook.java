package com.devicespooflab.hooks;

import android.os.Build;

import com.devicespooflab.hooks.hooks.AdvertisingIdHooks;
import com.devicespooflab.hooks.hooks.AppSetIdHooks;
import com.devicespooflab.hooks.hooks.BuildHooks;
import com.devicespooflab.hooks.hooks.EmulatorDetectionHooks;
import com.devicespooflab.hooks.hooks.HardwareHooks;
import com.devicespooflab.hooks.hooks.MediaDrmHooks;
import com.devicespooflab.hooks.hooks.PackageManagerHooks;
import com.devicespooflab.hooks.hooks.SettingsHooks;
import com.devicespooflab.hooks.hooks.SystemPropertiesHooks;
import com.devicespooflab.hooks.hooks.TelephonyHooks;
import com.devicespooflab.hooks.hooks.WebViewHooks;
import com.devicespooflab.hooks.utils.ConfigManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Main entry point for DeviceSpoofLabs-Hooks LSPosed module.
 *
 * STANDALONE MODULE - No Magisk dependency!
 *
 * This module hooks Android APIs to spoof ALL device identifiers and properties,
 * solving the problem where apps read properties from Zygote, bypassing Magisk.
 *
 * What this module spoofs:
 * - System properties (ro.build.*, ro.product.*, etc.) via SystemProperties reflection
 * - All Build.* static fields (FINGERPRINT, MODEL, DEVICE, VERSION.*, etc.)
 * - IMEI, MEID, IMSI, ICCID, Phone number (TelephonyManager)
 * - Google Advertising ID (AdvertisingIdClient)
 * - App Set ID (Android 11+)
 * - MediaDrm device unique ID (Widevine)
 * - ANDROID_ID, GSF ID (Settings.Secure)
 * - WebView User-Agent
 * - Hardware features (PackageManager)
 * - Emulator detection bypass (File.exists)
 *
 * Target Device: Google Pixel 7 Pro, Android 15
 */
public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "DeviceSpoofLab";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        // Log that we're loading for this package

        if ("com.google.android.gms".equals(lpparam.packageName)) {
            // 1. Сразу отсекаем процесс аттестации
            if (lpparam.processName != null && lpparam.processName.contains("unstable")) {
                 return;
             }

            boolean isTargetProcess = lpparam.processName != null && (lpparam.processName.contains("prime") || lpparam.processName.contains("persistent"));

            // Если это один из этих двух процессов — только тогда включаем фильтр по Биндеру
            if (isTargetProcess) {
                int callingUid = Binder.getCallingUid();
                int myUid = Process.myUid();
            
                // Если процесс GMS вызывает свойства сам для себя — подмену не делаем
                if (callingUid == myUid) return;

                String callingPackage = getPackageNameForUid(callingUid);

                // КРИТИЧЕСКИЙ ФИЛЬТР: Если вызов идет НЕ от Google One (red) — 
                // делаем жесткий return, прерывая хук. Пойдут родные свойства устройства.
                if (callingPackage == null || !callingPackage.equals("com.google.android.apps.subscriptions.red")) {
                    return; 
                }
            }
            
        }
        XposedBridge.log(TAG + ": Loading hooks for " + lpparam.packageName);

        // Initialize config (reads from file or uses embedded defaults)
        try {
            ConfigManager.init();
            XposedBridge.log(TAG + ": Config initialized successfully");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Failed to init config: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // Apply hooks in dependency order
        // 1. Core system property hooks (CRITICAL - catches reflection-based property reads)
        // This is SAFE and works for all apps
        try {
            SystemPropertiesHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ SystemPropertiesHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ SystemPropertiesHooks failed: " + e.getMessage());
        }

        // 2. Build class hooks (only Build.getSerial method)
        try {
            BuildHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ BuildHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ BuildHooks failed: " + e.getMessage());
        }

        // 3. Hardware hooks (CPU cores, RAM, architecture)
        try {
            HardwareHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ HardwareHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ HardwareHooks failed: " + e.getMessage());
        }

        // 4. Emulator detection hooks (hides emulator files)
        try {
            EmulatorDetectionHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ EmulatorDetectionHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ EmulatorDetectionHooks failed: " + e.getMessage());
        }

        // 5. Telephony hooks (IMEI, IMSI, ICCID, phone number)
        try {
            TelephonyHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ TelephonyHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ TelephonyHooks failed: " + e.getMessage());
        }

        // 6. Settings hooks (ANDROID_ID, GSF_ID)
        try {
            SettingsHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ SettingsHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ SettingsHooks failed: " + e.getMessage());
        }

        // 7. Advertising ID hooks (GAID)
        try {
            AdvertisingIdHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ AdvertisingIdHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ AdvertisingIdHooks failed: " + e.getMessage());
        }

        // 8. App Set ID hooks (Android 11+)
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                AppSetIdHooks.hook(lpparam);
                XposedBridge.log(TAG + ": ✅ AppSetIdHooks loaded");
            } catch (Exception e) {
                XposedBridge.log(TAG + ": ❌ AppSetIdHooks failed: " + e.getMessage());
            }
        }

        // 9. MediaDRM hooks (Widevine device ID)
        try {
            MediaDrmHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ MediaDrmHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ MediaDrmHooks failed: " + e.getMessage());
        }

        // 10. WebView hooks (User-Agent)
        try {
            WebViewHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ WebViewHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ WebViewHooks failed: " + e.getMessage());
        }

        // 11. PackageManager feature hooks (hardware features)
        try {
            PackageManagerHooks.hook(lpparam);
            XposedBridge.log(TAG + ": ✅ PackageManagerHooks loaded");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ❌ PackageManagerHooks failed: " + e.getMessage());
        }

        XposedBridge.log(TAG + ": 🎉 All hooks initialized for " + lpparam.packageName);
    }
}
