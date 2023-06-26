package ru.blays.bootloaderspoofer

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import java.security.cert.Certificate

class CertHook(private val hook: XC_MethodHook): XC_MethodHook() {
    @Suppress("UNCHECKED_CAST")
    override fun afterHookedMethod(param: MethodHookParam?) {
        try {
            val certificate: List<Certificate>? = param?.resultOrThrowable as List<Certificate>?
            certificate?.forEach { cert ->
                XposedHelpers.findAndHookMethod(
                    cert::class.java,
                    "getExtensionValue",
                    hook
                )
            }
        } catch (e: Exception) {
            XposedBridge.log(e)
        }
    }
}