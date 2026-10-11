package com.zyw.btanalyzer.hci

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicLong

class HciException(msg: String) : IOException(msg)

object Op {
    fun op(ogf: Int, ocf: Int) = (ogf shl 10) or ocf
    val INQUIRY = op(1, 0x01); val INQUIRY_CANCEL = op(1, 0x02); val DISCONNECT = op(1, 0x06)
    val REMOTE_NAME = op(1, 0x19); val REMOTE_NAME_CANCEL = op(1, 0x1A)
    val SET_EVENT_MASK = op(3, 0x01); val RESET = op(3, 0x03); val READ_LOCAL_NAME = op(3, 0x14)
    val WRITE_INQUIRY_MODE = op(3, 0x45); val WRITE_LE_HOST_SUPPORT = op(3, 0x6D)
    val CREATE_CONN = op(1, 0x05); val REJECT_CONN = op(1, 0x0A); val LINK_KEY_REPLY = op(1, 0x0B); val LINK_KEY_NEG = op(1, 0x0C)
    val PIN_REPLY = op(1, 0x0D); val PIN_NEG = op(1, 0x0E); val AUTH_REQUESTED = op(1, 0x11); val SET_ENCRYPTION = op(1, 0x13)
    val READ_REMOTE_FEATURES = op(1, 0x1B); val READ_REMOTE_VERSION = op(1, 0x1D)
    val IO_CAP_REPLY = op(1, 0x2B); val USER_CONFIRM_REPLY = op(1, 0x2C); val USER_CONFIRM_NEG = op(1, 0x2D)
    val PASSKEY_REPLY = op(1, 0x2E); val PASSKEY_NEG = op(1, 0x2F); val IO_CAP_NEG = op(1, 0x34)
    val WRITE_SSP_MODE = op(3, 0x56); val WRITE_SCAN_ENABLE = op(3, 0x1A)
    val READ_LOCAL_VERSION = op(4, 0x01); val READ_LOCAL_COMMANDS = op(4, 0x02); val READ_LOCAL_FEATURES = op(4, 0x03)
    val READ_BUFFER_SIZE = op(4, 0x05); val READ_BD_ADDR = op(4, 0x09)
    val LE_SET_EVENT_MASK = op(8, 0x01); val LE_READ_BUFFER_SIZE = op(8, 0x02); val LE_READ_FEATURES = op(8, 0x03)
    val LE_SET_SCAN_PARAMS = op(8, 0x0B); val LE_SET_SCAN_ENABLE = op(8, 0x0C)
    val LE_CREATE_CONN = op(8, 0x0D); val LE_CREATE_CONN_CANCEL = op(8, 0x0E)
    val LE_READ_WHITE_LIST_SIZE = op(8, 0x0F); val LE_READ_SUPPORTED_STATES = op(8, 0x1C)

    val names = mapOf(INQUIRY to "Inquiry", INQUIRY_CANCEL to "Inquiry Cancel", DISCONNECT to "Disconnect",
        REMOTE_NAME to "Remote Name Request", REMOTE_NAME_CANCEL to "Remote Name Cancel", SET_EVENT_MASK to "Set Event Mask",
        RESET to "Reset", READ_LOCAL_NAME to "Read Local Name", WRITE_INQUIRY_MODE to "Write Inquiry Mode",
        WRITE_LE_HOST_SUPPORT to "Write LE Host Support", READ_LOCAL_VERSION to "Read Local Version",
        READ_LOCAL_COMMANDS to "Read Local Supported Commands", READ_LOCAL_FEATURES to "Read Local Features",
        READ_BUFFER_SIZE to "Read Buffer Size", READ_BD_ADDR to "Read BD_ADDR", LE_SET_EVENT_MASK to "LE Set Event Mask",
        LE_READ_BUFFER_SIZE to "LE Read Buffer Size", LE_READ_FEATURES to "LE Read Local Features",
        LE_SET_SCAN_PARAMS to "LE Set Scan Parameters", LE_SET_SCAN_ENABLE to "LE Set Scan Enable",
        LE_CREATE_CONN to "LE Create Connection", LE_CREATE_CONN_CANCEL to "LE Create Connection Cancel",
        LE_READ_WHITE_LIST_SIZE to "LE Read White List Size", LE_READ_SUPPORTED_STATES to "LE Read Supported States",
        CREATE_CONN to "Create Connection", REJECT_CONN to "Reject Connection Request", LINK_KEY_REPLY to "Link Key Request Reply",
        LINK_KEY_NEG to "Link Key Request Negative Reply", PIN_REPLY to "PIN Code Request Reply", PIN_NEG to "PIN Code Negative Reply",
        AUTH_REQUESTED to "Authentication Requested", SET_ENCRYPTION to "Set Connection Encryption",
        READ_REMOTE_FEATURES to "Read Remote Supported Features", READ_REMOTE_VERSION to "Read Remote Version Information",
        IO_CAP_REPLY to "IO Capability Request Reply", USER_CONFIRM_REPLY to "User Confirmation Reply", USER_CONFIRM_NEG to "User Confirmation Negative Reply",
        PASSKEY_REPLY to "User Passkey Reply", PASSKEY_NEG to "User Passkey Negative Reply", IO_CAP_NEG to "IO Capability Negative Reply",
        WRITE_SSP_MODE to "Write Simple Pairing Mode", WRITE_SCAN_ENABLE to "Write Scan Enable")
    fun name(o: Int) = names[o] ?: "Opcode 0x%04X (OGF %d OCF 0x%03X)".format(o, o shr 10, o and 0x3ff)
}

object Evt {
    const val INQUIRY_COMPLETE = 0x01; const val INQUIRY_RESULT = 0x02; const val CONN_COMPLETE = 0x03
    const val DISCONN_COMPLETE = 0x05; const val REMOTE_NAME = 0x07; const val CMD_COMPLETE = 0x0E
    const val CMD_STATUS = 0x0F; const val HW_ERROR = 0x10; const val NUM_COMPLETED = 0x13
    const val INQUIRY_RESULT_RSSI = 0x22; const val EXT_INQUIRY_RESULT = 0x2F; const val LE_META = 0x3E
    val names = mapOf(1 to "Inquiry Complete", 2 to "Inquiry Result", 3 to "Connection Complete", 4 to "Connection Request",
        5 to "Disconnection Complete", 7 to "Remote Name Request Complete", 8 to "Encryption Change",
        0x0C to "Read Remote Version Complete", 0x0E to "Command Complete", 0x0F to "Command Status",
        0x10 to "Hardware Error", 0x13 to "Number Of Completed Packets", 0x1A to "Data Buffer Overflow",
        0x22 to "Inquiry Result with RSSI", 0x06 to "Authentication Complete", 0x0B to "Read Remote Features Complete",
        0x16 to "PIN Code Request", 0x17 to "Link Key Request", 0x18 to "Link Key Notification", 0x31 to "IO Capability Request",
        0x32 to "IO Capability Response", 0x33 to "User Confirmation Request", 0x34 to "User Passkey Request",
        0x36 to "Simple Pairing Complete", 0x3B to "User Passkey Notification", 0x30 to "Encryption Key Refresh Complete", 0x2F to "Extended Inquiry Result", 0x3E to "LE Meta")
    val leSub = mapOf(1 to "LE Connection Complete", 2 to "LE Advertising Report", 3 to "LE Connection Update Complete",
        4 to "LE Read Remote Features Complete", 5 to "LE Long Term Key Request")
}

/** HCI host core: command/response correlation, logging, ACL + L2CAP + ATT client. */
class HciController(
    private val send: (PktType, ByteArray) -> Unit,
    private val log: (HciRecord) -> Unit,
) {
    private val ids = AtomicLong()
    private val cmdMutex = Mutex()
    @Volatile private var pending: Pair<Int, CompletableDeferred<ByteArray>>? = null
    var onEvent: (ByteArray) -> Unit = {}
    var onAttNotify: (handle: Int, value: ByteArray, indication: Boolean) -> Unit = { _, _, _ -> }
    var aclMtu = 27
    var leMtu = 27
    var attMtu = 23
    /** Host->controller flow control (Number Of Completed Packets). leCredits==null => shared pool. */
    var aclCredits = java.util.concurrent.Semaphore(4)
    var leCredits: java.util.concurrent.Semaphore? = null
    val linkIsLe = java.util.concurrent.ConcurrentHashMap<Int, Boolean>()
    private val inFlight = java.util.concurrent.ConcurrentHashMap<Int, java.util.concurrent.atomic.AtomicInteger>()
    /** Data on CIDs other than ATT(4)/LE-sig(5): (handle, cid, payload) */
    var onL2cap: (Int, Int, ByteArray) -> Unit = { _, _, _ -> }
    private fun pool(handle: Int) = if (linkIsLe[handle] == true) (leCredits ?: aclCredits) else aclCredits
    fun linkClosed(handle: Int) {
        val n = inFlight.remove(handle)?.get() ?: 0
        if (n > 0) pool(handle).release(n)
        linkIsLe.remove(handle); reasm.remove(handle)
    }

    // ---------- commands ----------
    /** Sends a command and returns Command Complete return parameters (starting with status for most commands),
     *  or for Command Status-style commands a 1-byte array with the status. Throws on non-zero status if [check]. */
    suspend fun cmd(opcode: Int, params: ByteArray = ByteArray(0), timeoutMs: Long = 3000, check: Boolean = true): ByteArray =
        cmdMutex.withLock {
            val d = CompletableDeferred<ByteArray>()
            pending = opcode to d
            val pkt = ByteArray(3 + params.size)
            pkt[0] = opcode.toByte(); pkt[1] = (opcode shr 8).toByte(); pkt[2] = params.size.toByte()
            params.copyInto(pkt, 3)
            record(true, PktType.CMD, pkt)
            try {
                send(PktType.CMD, pkt)
                val r = try { withTimeout(timeoutMs) { d.await() } } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                    throw HciException("${Op.name(opcode)}: timeout")
                }
                if (check && r.isNotEmpty() && r.u8(0) != 0) throw HciException("${Op.name(opcode)}: ${Assigned.err(r.u8(0))}")
                r
            } finally { pending = null }
        }

    fun handleEvent(p: ByteArray) {
        record(false, PktType.EVT, p)
        val code = p.u8(0)
        when (code) {
            Evt.CMD_COMPLETE -> if (p.size >= 5) {
                val op = p.u16(3); pending?.let { (o, d) -> if (o == op) d.complete(p.copyOfRange(5, p.size)) }
            }
            Evt.CMD_STATUS -> if (p.size >= 6) {
                val op = p.u16(4); pending?.let { (o, d) -> if (o == op) d.complete(byteArrayOf(p[2])) }
            }
            Evt.NUM_COMPLETED -> if (p.size >= 3) {
                val n = p.u8(2)
                for (k in 0 until n) {
                    if (3 + n * 4 > p.size) break
                    val h = p.u16(3 + k * 2) and 0xfff; val c = p.u16(3 + n * 2 + k * 2)
                    val fl = inFlight[h]; val give = if (fl != null) minOf(c, fl.get()).also { fl.addAndGet(-it) } else 0
                    if (give > 0) pool(h).release(give)
                }
            }
        }
        onEvent(p)
    }

    // ---------- ACL / L2CAP / ATT ----------
    private val reasm = HashMap<Int, ByteArrayOutputStream>()
    @Volatile private var attPending: Pair<Set<Int>, CompletableDeferred<ByteArray>>? = null
    private val attMutex = Mutex()
    var attHandle = -1

    fun handleAcl(p: ByteArray) {
        record(false, PktType.ACL, p)
        val hf = p.u16(0); val handle = hf and 0x0fff; val pb = (hf shr 12) and 3
        val payload = p.copyOfRange(4, p.size)
        val buf = if (pb == 1) reasm[handle] ?: return else ByteArrayOutputStream().also { reasm[handle] = it }
        buf.write(payload)
        val a = buf.toByteArray()
        if (a.size < 4) return
        val l2len = a.u16(0); if (a.size < 4 + l2len) return
        reasm.remove(handle)
        val cid = a.u16(2); val data = a.copyOfRange(4, 4 + l2len)
        when (cid) {
            4 -> handleAtt(handle, data)
            5 -> handleLeSignaling(handle, data)
            else -> onL2cap(handle, cid, data)
        }
    }

    private fun handleLeSignaling(handle: Int, d: ByteArray) {
        if (d.size < 4) return
        val code = d.u8(0); val id = d.u8(1)
        // Connection Parameter Update Request (0x12): accept politely is complex; reject (result=1) is valid.
        if (code == 0x12) sendL2cap(handle, 5, bytesOf(0x13, id, 2, 0, 1, 0))
        else if (code != 0x13 && code != 0x01) sendL2cap(handle, 5, bytesOf(0x01, id, 2, 0, 0, 0)) // Command Reject: not understood
    }

    private fun handleAtt(handle: Int, d: ByteArray) {
        if (d.isEmpty()) return
        val op = d.u8(0)
        when (op) {
            0x1B, 0x1D -> { if (d.size >= 3) onAttNotify(d.u16(1), d.copyOfRange(3, d.size), op == 0x1D)
                if (op == 0x1D) sendL2cap(handle, 4, bytesOf(0x1E)) }
            0x02 -> sendL2cap(handle, 4, bytesOf(0x03) + le16(247))
            else -> {
                val p = attPending
                if (p != null && (op in p.first || op == 0x01)) { p.second.complete(d); return }
                // Unhandled request from peer (requests have even opcodes < 0x20 w/o cmd flag) -> Error: Request Not Supported
                if (op and 0x40 == 0 && op % 2 == 0 && op != 0x1E) sendL2cap(handle, 4, bytesOf(0x01, op, 0, 0, 0x06))
            }
        }
    }

    fun sendL2cap(handle: Int, cid: Int, data: ByteArray) {
        val l2 = le16(data.size) + le16(cid) + data
        val le = linkIsLe[handle] != false
        val mtu = if (le) leMtu else aclMtu
        var off = 0; var first = true
        while (off < l2.size) {
            val n = minOf(mtu, l2.size - off)
            // LE: PB=00 first (non-flushable); BR/EDR: PB=10 first automatically flushable; continuation PB=01
            val pb = if (!first) 0x1000 else if (le) 0x0000 else 0x2000
            val pkt = le16((handle and 0x0fff) or pb) + le16(n) + l2.copyOfRange(off, off + n)
            if (!pool(handle).tryAcquire(3, java.util.concurrent.TimeUnit.SECONDS)) throw HciException("ACL flow control: no controller buffers (NOCP timeout)")
            inFlight.getOrPut(handle) { java.util.concurrent.atomic.AtomicInteger() }.incrementAndGet()
            record(true, PktType.ACL, pkt); send(PktType.ACL, pkt)
            off += n; first = false
        }
    }

    /** ATT command without response (e.g. Write Command). */
    fun attCmd(pdu: ByteArray) { if (attHandle < 0) throw HciException("Not connected"); sendL2cap(attHandle, 4, pdu) }

    /** ATT request/response. Returns full response PDU; throws AttError on Error Response. */
    suspend fun att(req: ByteArray, expect: Int, timeoutMs: Long = 5000): ByteArray = attMutex.withLock {
        if (attHandle < 0) throw HciException("Not connected")
        val d = CompletableDeferred<ByteArray>()
        attPending = setOf(expect) to d
        try {
            sendL2cap(attHandle, 4, req)
            val r = try { withTimeout(timeoutMs) { d.await() } } catch (e: kotlinx.coroutines.TimeoutCancellationException) { throw HciException("ATT timeout") }
            if (r.u8(0) == 0x01 && r.size >= 5) throw AttError(r.u8(1), r.u16(2), r.u8(4))
            r
        } finally { attPending = null }
    }

    fun cancelAtt() { attPending?.second?.completeExceptionally(HciException("Disconnected")); attPending = null }

    // ---------- logging ----------
    private fun record(sent: Boolean, t: PktType, d: ByteArray) =
        log(HciRecord(ids.incrementAndGet(), System.currentTimeMillis(), sent, t, d, summarize(t, d)))

    companion object {
        val attOps = mapOf(0x01 to "Error Response", 0x02 to "Exchange MTU Req", 0x03 to "Exchange MTU Rsp",
            0x04 to "Find Information Req", 0x05 to "Find Information Rsp", 0x06 to "Find By Type Value Req", 0x07 to "Find By Type Value Rsp",
            0x08 to "Read By Type Req", 0x09 to "Read By Type Rsp", 0x0A to "Read Req", 0x0B to "Read Rsp", 0x0C to "Read Blob Req",
            0x0D to "Read Blob Rsp", 0x10 to "Read By Group Type Req", 0x11 to "Read By Group Type Rsp", 0x12 to "Write Req",
            0x13 to "Write Rsp", 0x52 to "Write Cmd", 0x1B to "Notification", 0x1D to "Indication", 0x1E to "Confirmation")
        private fun attHandleOf(d: ByteArray): String = runCatching {
            val op = d.u8(8)
            when (op) {
                0x0A, 0x0C -> " handle=0x%04X".format(d.u16(9))
                0x12, 0x52, 0x1B, 0x1D -> " handle=0x%04X value=%s".format(d.u16(9), short(d.copyOfRange(11, d.size)))
                0x0B, 0x0D -> " value=" + short(d.copyOfRange(9, d.size))
                0x02, 0x03 -> " mtu=${d.u16(9)}"
                0x01 -> " req=%s handle=0x%04X %s".format(attOps[d.u8(9)] ?: "?", d.u16(10), Assigned.attErrors[d.u8(12)] ?: "0x%02X".format(d.u8(12)))
                0x08, 0x10, 0x04 -> " 0x%04X-0x%04X".format(d.u16(9), d.u16(11)) + if (d.size >= 15) " type=" + uuidString(d.copyOfRange(13, d.size)) else ""
                else -> ""
            }
        }.getOrDefault("")
        private fun short(b: ByteArray) = if (b.size > 20) b.copyOfRange(0, 20).hex("") + "…(${b.size}B)" else b.hex("")

        fun l2sig(c: Int) = mapOf(1 to "Command Reject", 2 to "Connection Req", 3 to "Connection Rsp", 4 to "Configure Req", 5 to "Configure Rsp",
            6 to "Disconnection Req", 7 to "Disconnection Rsp", 0x0A to "Information Req", 0x0B to "Information Rsp",
            0x12 to "Conn Param Update Req", 0x13 to "Conn Param Update Rsp")[c] ?: "code 0x%02X".format(c)

        /** Category used by viewers: ATT / SMP / L2CAP / ACL / CMD / EVT */
        fun category(t: PktType, d: ByteArray): String = when (t) {
            PktType.CMD -> "CMD"; PktType.EVT -> "EVT"
            PktType.ACL -> if (d.size >= 8 && ((d.u16(0) shr 12) and 3) != 1) when (d.u16(6)) { 4 -> "ATT"; 6, 7 -> "SMP"; else -> "L2CAP" } else "ACL"
        }
        fun aclHandle(t: PktType, d: ByteArray): Int = runCatching {
            when {
                t == PktType.ACL -> d.u16(0) and 0xfff
                t == PktType.EVT && d.u8(0) == Evt.LE_META && d.u8(2) == 1 -> d.u16(4) and 0xfff
                t == PktType.EVT && d.u8(0) in setOf(3, 5, 6, 8, 0x0B, 0x0C) -> d.u16(3) and 0xfff
                t == PktType.CMD && d.u16(0) in setOf(Op.DISCONNECT, Op.AUTH_REQUESTED, Op.SET_ENCRYPTION, Op.READ_REMOTE_FEATURES, Op.READ_REMOTE_VERSION) -> d.u16(3) and 0xfff
                else -> -1
            }
        }.getOrDefault(-1)

        /** Human-readable field breakdown for the detail view. */
        fun details(t: PktType, d: ByteArray): List<Pair<String, String>> = runCatching {
            val out = mutableListOf<Pair<String, String>>()
            when (t) {
                PktType.CMD -> { val o = d.u16(0)
                    out += "Opcode" to "0x%04X (OGF 0x%02X, OCF 0x%03X)".format(o, o shr 10, o and 0x3ff)
                    out += "Command" to Op.name(o); out += "Param length" to "${d.u8(2)} bytes"
                    if (d.size > 3) out += "Parameters" to d.copyOfRange(3, d.size).hex() }
                PktType.EVT -> { val c = d.u8(0)
                    out += "Event" to "${Evt.names[c] ?: "?"} (0x%02X)".format(c); out += "Param length" to "${d.u8(1)} bytes"
                    when (c) {
                        Evt.CMD_COMPLETE -> { out += "For command" to Op.name(d.u16(3)); if (d.size > 5) out += "Status" to Assigned.err(d.u8(5))
                            if (d.size > 6) out += "Return params" to d.copyOfRange(6, d.size).hex() }
                        Evt.CMD_STATUS -> { out += "For command" to Op.name(d.u16(4)); out += "Status" to Assigned.err(d.u8(2)) }
                        Evt.DISCONN_COMPLETE -> { out += "Handle" to "0x%03X".format(d.u16(3)); out += "Reason" to Assigned.err(d.u8(5)) }
                        Evt.LE_META -> { out += "Subevent" to (Evt.leSub[d.u8(2)] ?: "0x%02X".format(d.u8(2)))
                            if (d.u8(2) == 2 && d.size > 12) { out += "Address" to d.addr(6); out += "RSSI" to "${d.s8(d.size - 1)} dBm" }
                            if (d.u8(2) == 1 && d.size > 12) { out += "Status" to Assigned.err(d.u8(3)); out += "Handle" to "0x%03X".format(d.u16(4)); out += "Peer" to d.addr(8) } }
                    } }
                PktType.ACL -> { val hf = d.u16(0)
                    out += "Handle" to "0x%03X".format(hf and 0xfff); out += "PB flag" to "${(hf shr 12) and 3}"
                    out += "Length" to "${d.u16(2)} bytes"
                    if (d.size >= 8 && ((hf shr 12) and 3) != 1) {
                        val cid = d.u16(6); out += "L2CAP CID" to "0x%04X ".format(cid) + when (cid) { 4 -> "(ATT)"; 5 -> "(LE signaling)"; 6 -> "(SMP)"; 1 -> "(signaling)"; else -> "" }
                        if (cid == 4 && d.size > 8) { out += "ATT" to (attOps[d.u8(8)] ?: "0x%02X".format(d.u8(8)))
                            if (d.size > 9) out += "ATT params" to d.copyOfRange(9, d.size).hex() }
                    }
                }
            }
            out
        }.getOrDefault(emptyList())

        fun summarize(t: PktType, d: ByteArray): String = runCatching {
            when (t) {
                PktType.CMD -> Op.name(d.u16(0))
                PktType.EVT -> {
                    val c = d.u8(0)
                    when (c) {
                        Evt.CMD_COMPLETE -> "Command Complete: ${Op.name(d.u16(3))}" + (if (d.size > 5) " status=${Assigned.err(d.u8(5))}" else "")
                        Evt.CMD_STATUS -> "Command Status: ${Op.name(d.u16(4))} status=${Assigned.err(d.u8(2))}"
                        Evt.LE_META -> Evt.leSub[d.u8(2)] ?: "LE Meta sub 0x%02X".format(d.u8(2))
                        else -> Evt.names[c] ?: "Event 0x%02X".format(c)
                    }
                }
                PktType.ACL -> {
                    val h = d.u16(0) and 0xfff
                    val cid = if (d.size >= 8 && ((d.u16(0) shr 12) and 3) != 1) d.u16(6) else -1
                    "ACL h=0x%03X len=%d".format(h, d.u16(2)) + when (cid) { 4 -> " · ATT " + (attOps[d.u8(8)] ?: "op 0x%02X".format(d.u8(8))) + attHandleOf(d); 5 -> " · LE sig " + l2sig(d.u8(8)); -1 -> " (continuation)"; 1 -> " · L2CAP sig " + l2sig(d.u8(8)); 6 -> " · SMP"; else -> " · L2CAP CID=0x%04X".format(cid) }
                }
            }
        }.getOrDefault("?")
    }
}

class AttError(val reqOp: Int, val handle: Int, val code: Int) :
    IOException("ATT error 0x%02X %s (handle 0x%04X)".format(code, Assigned.attErrors[code] ?: "", handle))
