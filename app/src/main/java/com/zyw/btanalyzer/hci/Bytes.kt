package com.zyw.btanalyzer.hci

fun ByteArray.hex(sep: String = " ") = joinToString(sep) { "%02X".format(it.toInt() and 0xff) }
fun ByteArray.u8(i: Int) = this[i].toInt() and 0xff
fun ByteArray.u16(i: Int) = u8(i) or (u8(i + 1) shl 8)
fun ByteArray.s8(i: Int) = this[i].toInt()
fun ByteArray.u24(i: Int) = u16(i) or (u8(i + 2) shl 16)
fun ByteArray.u32(i: Int) = u16(i).toLong() or (u16(i + 2).toLong() shl 16)
/** Little-endian 6-byte BD_ADDR -> "AA:BB:CC:DD:EE:FF" */
fun ByteArray.addr(i: Int) = (5 downTo 0).joinToString(":") { "%02X".format(u8(i + it)) }
fun addrBytes(s: String): ByteArray = s.split(":").map { it.toInt(16).toByte() }.reversed().toByteArray()
/** Little-endian UUID bytes -> string */
fun uuidString(b: ByteArray): String = when (b.size) {
    2 -> "%04X".format(b.u16(0))
    4 -> "%08X".format(b.u32(0))
    16 -> b.reversedArray().hex("").lowercase().let { "${it.substring(0,8)}-${it.substring(8,12)}-${it.substring(12,16)}-${it.substring(16,20)}-${it.substring(20)}" }
    else -> b.hex("")
}
fun bytesOf(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
fun le16(v: Int) = bytesOf(v and 0xff, (v shr 8) and 0xff)
