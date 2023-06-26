package ru.blays.bootloaderspoofer

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.security.KeyStore

class Xposed: IXposedHookLoadPackage {

    private val bytesHook = BytesHook()

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam?) {
        try {
            XposedBridge.log("Bootloader Spoofer | start hook for: ${lpparam?.packageName}")
            val certHook = CertHook(bytesHook)
            val keystore = KeyStore.getInstance("AndroidKeyStore")
            val keyStoreSpi = XposedHelpers.getObjectField(keystore, "keyStoreSpi")
            XposedHelpers.findAndHookMethod(
                keyStoreSpi::class.java,
                "engineGetCertificateChain",
                String::class.java,
                certHook
            )
        } catch (e: Exception) {
            XposedBridge.log(e)
        }
    }
}