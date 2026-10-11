package com.zyw.btanalyzer.hci

import java.io.DataOutputStream
import java.io.OutputStream

enum class PktType(val h4: Int, val label: String) { CMD(1, "CMD"), ACL(2, "ACL"), EVT(4, "EVT") }

data class HciRecord(val id: Long, val timeMs: Long, val sent: Boolean, val type: PktType, val data: ByteArray, val summary: String)

/** btsnoop v1, datalink 1002 (HCI UART / H4), readable by Wireshark. */
object BtSnoop {
    private const val EPOCH_DELTA_US = 0x00dcddb30f2f8000L // 0000-01-01 -> 1970-01-01 in µs
    fun write(out: OutputStream, recs: List<HciRecord>) {
        val d = DataOutputStream(out.buffered())
        d.write("btsnoop".toByteArray()); d.writeByte(0)
        d.writeInt(1); d.writeInt(1002)
        for (r in recs) {
            val len = r.data.size + 1
            d.writeInt(len); d.writeInt(len)
            val flags = (if (r.sent) 0 else 1) or (if (r.type == PktType.CMD || r.type == PktType.EVT) 2 else 0)
            d.writeInt(flags); d.writeInt(0)
            d.writeLong(r.timeMs * 1000 + EPOCH_DELTA_US)
            d.writeByte(r.type.h4); d.write(r.data)
        }
        d.flush()
    }
}
