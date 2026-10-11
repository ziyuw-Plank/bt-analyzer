package com.zyw.btanalyzer.hci

data class AdItem(val type: Int, val typeName: String, val raw: ByteArray, val decoded: String)

data class AdInfo(
    val name: String? = null,
    val txPower: Int? = null,
    val items: List<AdItem> = emptyList(),
    val tags: List<String> = emptyList(),
)

object AdParser {
    fun parse(data: ByteArray): AdInfo {
        var i = 0; var name: String? = null; var tx: Int? = null
        val items = mutableListOf<AdItem>(); val tags = mutableListOf<String>()
        while (i < data.size) {
            val len = data.u8(i); if (len == 0) break
            if (i + 1 + len > data.size) { items += AdItem(-1, "Malformed", data.copyOfRange(i, data.size), "truncated"); break }
            val t = data.u8(i + 1); val v = data.copyOfRange(i + 2, i + 1 + len)
            val (tn, dec) = decode(t, v, tags)
            if (t == 0x08 || t == 0x09) { if (name == null || t == 0x09) name = String(v, Charsets.UTF_8) }
            if (t == 0x0A && v.isNotEmpty()) tx = v.s8(0)
            items += AdItem(t, tn, v, dec)
            i += 1 + len
        }
        return AdInfo(name, tx, items, tags.distinct())
    }

    private fun uuids(v: ByteArray, w: Int) = (0 until v.size / w).joinToString(", ") {
        val u = uuidString(v.copyOfRange(it * w, it * w + w)); Assigned.uuidName(u)?.let { n -> "$u ($n)" } ?: u
    }

    private fun decode(t: Int, v: ByteArray, tags: MutableList<String>): Pair<String, String> = when (t) {
        0x01 -> "Flags" to buildList {
            val f = if (v.isNotEmpty()) v.u8(0) else 0
            if (f and 1 != 0) add("LE Limited Disc"); if (f and 2 != 0) add("LE General Disc")
            if (f and 4 != 0) add("BR/EDR Not Supported"); if (f and 8 != 0) add("LE+BR/EDR (Controller)"); if (f and 16 != 0) add("LE+BR/EDR (Host)")
        }.joinToString(", ")
        0x02, 0x03 -> "16-bit UUIDs" + (if (t == 2) " (partial)" else "") to uuids(v, 2).also { if (v.size >= 2 && v.u16(0) == 0xFD6F) tags += "Exposure Notification" }
        0x04, 0x05 -> "32-bit UUIDs" to uuids(v, 4)
        0x06, 0x07 -> "128-bit UUIDs" to uuids(v, 16)
        0x08 -> "Short Name" to String(v, Charsets.UTF_8)
        0x09 -> "Complete Name" to String(v, Charsets.UTF_8)
        0x0A -> "Tx Power" to (if (v.isNotEmpty()) "${v.s8(0)} dBm" else "")
        0x0D -> "Class of Device" to (if (v.size >= 3) Assigned.cod(v.u24(0)) else v.hex())
        0x14 -> "Solicited 16-bit UUIDs" to uuids(v, 2)
        0x16 -> "Service Data (16-bit)" to serviceData16(v, tags)
        0x19 -> "Appearance" to (if (v.size >= 2) "0x%04X".format(v.u16(0)) else "")
        0x1B -> "LE Device Address" to (if (v.size >= 7) v.addr(0) else v.hex())
        0x20 -> "Service Data (32-bit)" to v.hex()
        0x21 -> "Service Data (128-bit)" to v.hex()
        0x24 -> "URI" to String(v, Charsets.UTF_8)
        0xFF -> "Manufacturer Data" to manufacturer(v, tags)
        else -> "Type 0x%02X".format(t) to v.hex()
    }

    private fun manufacturer(v: ByteArray, tags: MutableList<String>): String {
        if (v.size < 2) return v.hex()
        val cid = v.u16(0); val p = v.copyOfRange(2, v.size)
        val base = "Company 0x%04X %s".format(cid, Assigned.company(cid))
        tags += Assigned.company(cid)
        if (cid == 0x004C && p.size >= 23 && p.u8(0) == 0x02 && p.u8(1) == 0x15) {
            tags += "iBeacon"
            val uuid = p.copyOfRange(2, 18).hex("").lowercase().let { "${it.substring(0,8)}-${it.substring(8,12)}-${it.substring(12,16)}-${it.substring(16,20)}-${it.substring(20)}" }
            val major = (p.u8(18) shl 8) or p.u8(19); val minor = (p.u8(20) shl 8) or p.u8(21)
            return "$base\niBeacon UUID=$uuid\nMajor=$major Minor=$minor TxPower@1m=${p.s8(22)} dBm"
        }
        if (cid == 0x004C && p.isNotEmpty()) {
            val kind = when (p.u8(0)) { 0x07 -> "Proximity Pairing (AirPods)"; 0x10 -> "Nearby Info"; 0x12 -> "Find My"; 0x0C -> "Handoff"; 0x09 -> "AirPlay"; 0x0F -> "Nearby Action"; else -> null }
            if (kind != null) { tags += "Apple $kind"; return "$base\nApple $kind\n${p.hex()}" }
        }
        return "$base\n${p.hex()}"
    }

    private fun serviceData16(v: ByteArray, tags: MutableList<String>): String {
        if (v.size < 2) return v.hex()
        val u = v.u16(0); val d = v.copyOfRange(2, v.size)
        val head = "UUID %04X %s".format(u, Assigned.services16[u] ?: "")
        if (u == 0xFEAA && d.isNotEmpty()) {
            tags += "Eddystone"
            return head + "\n" + when (d.u8(0)) {
                0x00 -> if (d.size >= 18) "Eddystone-UID tx=${d.s8(1)} ns=${d.copyOfRange(2, 12).hex("")} inst=${d.copyOfRange(12, 18).hex("")}" else d.hex()
                0x10 -> if (d.size >= 3) "Eddystone-URL tx=${d.s8(1)} ${eddyUrl(d.copyOfRange(2, d.size))}" else d.hex()
                0x20 -> if (d.size >= 14) "Eddystone-TLM batt=${(d.u8(2) shl 8) or d.u8(3)}mV temp=%.2f°C adv=%d secs=%.1f".format(
                    d.s8(4) + d.u8(5) / 256.0,
                    ((d.u8(6).toLong() shl 24) or (d.u8(7).toLong() shl 16) or (d.u8(8).toLong() shl 8) or d.u8(9).toLong()),
                    ((d.u8(10).toLong() shl 24) or (d.u8(11).toLong() shl 16) or (d.u8(12).toLong() shl 8) or d.u8(13).toLong()) / 10.0) else d.hex()
                0x30 -> "Eddystone-EID ${d.hex()}"
                else -> d.hex()
            }
        }
        return "$head\n${d.hex()}"
    }

    private fun eddyUrl(b: ByteArray): String {
        val pre = listOf("http://www.", "https://www.", "http://", "https://")
        val exp = listOf(".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/", ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov")
        val sb = StringBuilder(pre.getOrElse(b.u8(0)) { "" })
        for (k in 1 until b.size) { val c = b.u8(k); if (c < exp.size) sb.append(exp[c]) else sb.append(c.toChar()) }
        return sb.toString()
    }
}
