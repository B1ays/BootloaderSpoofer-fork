package ru.blays.bootloaderspoofer

import com.google.common.primitives.Bytes
import de.robv.android.xposed.XC_MethodHook
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject

class BytesHook: XC_MethodHook() {

    override fun afterHookedMethod(param: MethodHookParam?) {

        val bytes = param?.resultOrThrowable as ByteArray?
        val oid = param?.args?.get(0) as String?

        if (oid == null || bytes == null) return

        if (oid != "1.3.6.1.4.1.11129.2.1.17") return

        var asn1Sequence: ASN1Sequence?
        ASN1InputStream(bytes).use { asn1InputStream ->
            val asn1OctetString = asn1InputStream.readObject() as ASN1OctetString?
            ASN1InputStream(asn1OctetString?.octets).use { asn1InputStream1 ->
                asn1Sequence = asn1InputStream1.readObject() as ASN1Sequence?
            }
        }

        if (asn1Sequence == null) return

        val teeEnforced = asn1Sequence?.getObjectAt(7) as ASN1Sequence? ?: return

        var rootOfTrust: ASN1Sequence? = null
        for (encodable in teeEnforced) {
            val asn1TaggedObject = encodable as ASN1TaggedObject?
            if (asn1TaggedObject?.tagNo == 704) {
                rootOfTrust = asn1TaggedObject.baseObject as ASN1Sequence?
                break
            }
        }

        if (rootOfTrust == null) return

        val rootOfTrustBytes = rootOfTrust.encoded
        val rootOfTrustIndex = Bytes.indexOf(bytes, rootOfTrustBytes)

        val deviceLocked = rootOfTrust.getObjectAt(1) as ASN1Boolean?
        val verifiedBootState = rootOfTrust.getObjectAt(2) as ASN1Enumerated?

        if (deviceLocked == null || verifiedBootState == null) return

        val deviceLockedIndex = Bytes.indexOf(rootOfTrustBytes, deviceLocked.encoded)
        val verifiedBootStateIndex = Bytes.indexOf(rootOfTrustBytes, verifiedBootState.encoded)

        val patchDeviceLockedIndex = rootOfTrustIndex + deviceLockedIndex + 2
        val patchVerifiedBootStateIndex = rootOfTrustIndex + verifiedBootStateIndex + 2

        bytes[patchDeviceLockedIndex] = 1
        bytes[patchVerifiedBootStateIndex] = 0

        param?.result = bytes
    }
}