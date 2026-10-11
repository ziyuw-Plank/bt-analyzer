package com.zyw.btanalyzer.hci

/** Minimal SDP data-element parser (Core Vol 3 Part B §3). */
sealed class De {
    data class UInt(val v: Long, val size: Int) : De()
    data class SInt(val v: Long) : De()
    data class Uuid(val s: String) : De()
    data class Str(val s: String) : De()
    data class Bool(val b: Boolean) : De()
    data class Seq(val items: List<De>, val alt: Boolean = false) : De()
    data class Url(val s: String) : De()
    object Nil : De()
}

data class SdpRecord(val handle: Long?, val name: String?, val classes: List<String>, val rfcomm: Int?, val psm: Int?, val profiles: List<String>)

object Sdp {
    fun parse(b: ByteArray, start: Int = 0): Pair<De, Int> {
        val h = b.u8(start); val type = h shr 3; val sz = h and 7
        var i = start + 1
        val len: Int = when (sz) {
            0 -> if (type == 0) 0 else 1; 1 -> 2; 2 -> 4; 3 -> 8; 4 -> 16
            5 -> b.u8(i).also { i += 1 }; 6 -> ((b.u8(i) shl 8) or b.u8(i + 1)).also { i += 2 }
            else -> ((b.u8(i) shl 24) or (b.u8(i + 1) shl 16) or (b.u8(i + 2) shl 8) or b.u8(i + 3)).also { i += 4 }
        }
        fun be(n: Int): Long { var v = 0L; for (k in 0 until n) v = (v shl 8) or b.u8(i + k).toLong(); return v }
        val de: De = when (type) {
            0 -> De.Nil
            1 -> De.UInt(be(minOf(len, 8)), len)
            2 -> De.SInt(be(minOf(len, 8)))
            3 -> De.Uuid(when (len) { 2 -> "%04X".format(be(2)); 4 -> "%08X".format(be(4))
                else -> b.copyOfRange(i, i + 16).hex("").lowercase().let { "${it.substring(0,8)}-${it.substring(8,12)}-${it.substring(12,16)}-${it.substring(16,20)}-${it.substring(20)}" } })
            4 -> De.Str(String(b, i, len, Charsets.UTF_8).trimEnd('\u0000'))
            5 -> De.Bool(b.u8(i) != 0)
            6, 7 -> { val items = mutableListOf<De>(); var j = i; while (j < i + len) { val (d, n) = parse(b, j); items += d; j = n }; De.Seq(items, type == 7) }
            8 -> De.Url(String(b, i, len, Charsets.UTF_8))
            else -> De.Nil
        }
        return de to (i + len)
    }

    val uuidNames = mapOf(0x1101 to "Serial Port", 0x1103 to "Dial-up Networking", 0x1105 to "OBEX Object Push", 0x1106 to "OBEX File Transfer",
        0x1108 to "Headset", 0x110A to "Audio Source (A2DP)", 0x110B to "Audio Sink (A2DP)", 0x110C to "AVRCP Target", 0x110E to "AVRCP",
        0x110F to "AVRCP Controller", 0x1112 to "Headset AG", 0x1115 to "PANU", 0x1116 to "NAP", 0x111E to "Handsfree", 0x111F to "Handsfree AG",
        0x1124 to "HID", 0x112D to "SIM Access", 0x112F to "Phonebook Access PSE", 0x1132 to "Message Access Server", 0x1200 to "PnP Information",
        0x1800 to "Generic Access", 0x1801 to "Generic Attribute", 0x0100 to "L2CAP", 0x0003 to "RFCOMM", 0x0008 to "OBEX", 0x0017 to "AVCTP", 0x0019 to "AVDTP", 0x000F to "BNEP")
    fun uuidLabel(u: String): String { val v = if (u.length <= 8) u.toLong(16).toInt() else Assigned.short16(u) ?: -1; return uuidNames[v]?.let { "$it ($u)" } ?: u }

    /** attributeLists: DES of records, each DES of (attrId, value) pairs. */
    fun records(attributeLists: ByteArray): List<SdpRecord> {
        if (attributeLists.isEmpty()) return emptyList()
        val (top, _) = parse(attributeLists)
        val recs = (top as? De.Seq)?.items ?: return emptyList()
        return recs.mapNotNull { r ->
            val items = (r as? De.Seq)?.items ?: return@mapNotNull null
            val attrs = HashMap<Int, De>()
            for (k in 0 until items.size - 1 step 2) (items[k] as? De.UInt)?.let { attrs[it.v.toInt()] = items[k + 1] }
            val classes = ((attrs[0x0001] as? De.Seq)?.items ?: emptyList()).mapNotNull { (it as? De.Uuid)?.s }.map(::uuidLabel)
            var rf: Int? = null; var psm: Int? = null
            ((attrs[0x0004] as? De.Seq)?.items ?: emptyList()).forEach { p ->
                val l = (p as? De.Seq)?.items ?: return@forEach
                val u = (l.firstOrNull() as? De.Uuid)?.s ?: return@forEach
                val param = (l.getOrNull(1) as? De.UInt)?.v?.toInt()
                if (u.equals("0003", true)) rf = param
                if (u.equals("0100", true)) psm = param
            }
            val profiles = ((attrs[0x0009] as? De.Seq)?.items ?: emptyList()).mapNotNull { pd ->
                val l = (pd as? De.Seq)?.items ?: return@mapNotNull null
                val u = (l.firstOrNull() as? De.Uuid)?.s ?: return@mapNotNull null
                val v = (l.getOrNull(1) as? De.UInt)?.v?.toInt() ?: 0
                "${uuidLabel(u)} v${v shr 8}.${v and 0xff}"
            }
            SdpRecord((attrs[0x0000] as? De.UInt)?.v, (attrs[0x0100] as? De.Str)?.s, classes, rf, psm, profiles)
        }
    }
}
