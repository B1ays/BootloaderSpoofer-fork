package ru.blays.bootloaderspoofer

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import java.security.cert.Certificate

class CertHook(private val hook: XC_MethodHook): XC_MethodHook() {
    @Suppress("UNCHECKED_CAST")
    override fun afterHookedMethod(param: MethodHookParam?) {
        try {
            val certificates = param!!.resultOrThrowable as Array<Certificate>
            certificates.forEach { certificate ->
                XposedHelpers.findAndHookMethod(
                    certificate::class.java,
                    "getExtensionValue",
                    String::class.java,
                    hook
                )
            }
        } catch (e: Exception) {
            XposedBridge.log(e)
        }
    }
}