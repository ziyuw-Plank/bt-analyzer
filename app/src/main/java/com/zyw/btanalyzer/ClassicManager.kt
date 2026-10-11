package com.zyw.btanalyzer

import android.content.SharedPreferences
import com.zyw.btanalyzer.hci.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

enum class ClState { IDLE, CONNECTING, CONNECTED }
data class ClassicConn(
    val address: String, val state: ClState = ClState.IDLE, val handle: Int = -1,
    val bonded: Boolean = false, val keyType: Int? = null, val authenticated: Boolean = false, val encrypted: Boolean = false,
    val pairing: String? = null, val version: String? = null, val features: List<String> = emptyList(),
    val sdp: List<SdpRecord>? = null, val sdpBusy: Boolean = false, val error: String? = null,
)
enum class PromptKind { CONFIRM, PASSKEY_ENTRY, PASSKEY_DISPLAY, PIN }
data class PairingPrompt(val kind: PromptKind, val address: String, val value: Long? = null)

/** BR/EDR connection, SSP/legacy pairing, link-key store and SDP client. */
class ClassicManager(
    private val scope: CoroutineScope,
    private val hci: () -> HciController,
    private val prefs: SharedPreferences,
    private val msg: (String) -> Unit,
) {
    val conns = MutableStateFlow<Map<String, ClassicConn>>(emptyMap())
    val prompt = MutableStateFlow<PairingPrompt?>(null)
    private val connWaiters = ConcurrentHashMap<String, CompletableDeferred<ByteArray>>()
    private val remoteIo = ConcurrentHashMap<String, Int>()
    private val sigId = AtomicInteger(1)
    private val sigWait = ConcurrentHashMap<Int, CompletableDeferred<ByteArray>>()
    private val cidMap = ConcurrentHashMap<Int, Int>() // local cid -> remote cid
    private val dataWait = ConcurrentHashMap<Int, CompletableDeferred<ByteArray>>()
    private val nextCid = AtomicInteger(0x0040)

    private fun get(a: String) = conns.value[a] ?: ClassicConn(a, bonded = prefs.contains(a))
    private fun upd(a: String, f: (ClassicConn) -> ClassicConn) { synchronized(this) { conns.value = conns.value + (a to f(get(a))) } }
    private fun byHandle(h: Int) = conns.value.values.firstOrNull { it.handle == h }
    fun ensure(a: String) { if (!conns.value.containsKey(a)) upd(a) { it } }

    private fun launch(block: suspend CoroutineScope.() -> Unit) = scope.launch(Dispatchers.IO) {
        try { block() } catch (e: CancellationException) { throw e } catch (e: Throwable) { msg(e.message ?: e.toString()) }
    }

    // ------------ public actions ------------
    suspend fun connectNow(a: String): Int {
        get(a).takeIf { it.state == ClState.CONNECTED }?.let { return it.handle }
        val h = hci(); upd(a) { it.copy(state = ClState.CONNECTING, error = null) }
        val w = CompletableDeferred<ByteArray>(); connWaiters[a] = w
        try {
            h.cmd(Op.CREATE_CONN, addrBytes(a) + bytesOf(0x18, 0xCC, 0x01, 0x00, 0x00, 0x00, 0x01))
            val ev = withTimeoutOrNull(20000) { w.await() } ?: run { h.cmd(Op.op(1, 0x08), addrBytes(a), check = false); throw HciException("Connect timeout") }
            if (ev.u8(2) != 0) throw HciException("Connect failed: ${Assigned.err(ev.u8(2))}")
            return ev.u16(3) and 0xfff
        } catch (e: Exception) { upd(a) { it.copy(state = ClState.IDLE, error = e.message) }; throw e } finally { connWaiters.remove(a) }
    }
    fun connect(a: String) = launch { connectNow(a) }
    fun disconnect(a: String) = launch { val c = get(a); if (c.handle >= 0) hci().cmd(Op.DISCONNECT, le16(c.handle) + bytesOf(0x13), check = false) }
    fun pair(a: String) = launch {
        val handle = connectNow(a)
        upd(a) { it.copy(pairing = "Authenticating…") }
        hci().cmd(Op.AUTH_REQUESTED, le16(handle))
    }
    fun encrypt(a: String) = launch { val c = get(a); if (c.handle < 0) throw HciException("Not connected"); hci().cmd(Op.SET_ENCRYPTION, le16(c.handle) + bytesOf(1)) }
    fun remoteInfo(a: String) = launch {
        val handle = connectNow(a)
        hci().cmd(Op.READ_REMOTE_VERSION, le16(handle)); hci().cmd(Op.READ_REMOTE_FEATURES, le16(handle))
    }
    fun forget(a: String) { prefs.edit().remove(a).remove("$a.type").apply(); upd(a) { it.copy(bonded = false, keyType = null) }; msg("Link key removed") }

    fun answer(accept: Boolean, input: String? = null) = launch {
        val p = prompt.value ?: return@launch; prompt.value = null
        val h = hci(); val ad = addrBytes(p.address)
        when (p.kind) {
            PromptKind.CONFIRM -> h.cmd(if (accept) Op.USER_CONFIRM_REPLY else Op.USER_CONFIRM_NEG, ad, check = false)
            PromptKind.PASSKEY_ENTRY -> { val v = input?.toLongOrNull()
                if (accept && v != null && v in 0..999999) h.cmd(Op.PASSKEY_REPLY, ad + le16((v and 0xffff).toInt()) + le16((v shr 16).toInt()), check = false)
                else h.cmd(Op.PASSKEY_NEG, ad, check = false) }
            PromptKind.PIN -> { val pin = (input ?: "").toByteArray()
                if (accept && pin.size in 1..16) h.cmd(Op.PIN_REPLY, ad + bytesOf(pin.size) + pin + ByteArray(16 - pin.size), check = false)
                else h.cmd(Op.PIN_NEG, ad, check = false) }
            PromptKind.PASSKEY_DISPLAY -> {}
        }
        if (!accept) upd(p.address) { it.copy(pairing = "Rejected by user") }
    }

    // ------------ HCI events ------------
    fun onEvent(p: ByteArray) {
        val h = hci()
        when (p.u8(0)) {
            Evt.CONN_COMPLETE -> if (p.size >= 13) {
                val a = p.addr(5); val handle = p.u16(3) and 0xfff
                if (p.u8(2) == 0) { h.linkIsLe[handle] = false
                    upd(a) { it.copy(state = ClState.CONNECTED, handle = handle, encrypted = p.u8(12) != 0, error = null) } }
                connWaiters[a]?.complete(p)
            }
            0x04 -> if (p.size >= 8) launch { h.cmd(Op.REJECT_CONN, addrBytes(p.addr(2)) + bytesOf(0x0F), check = false) }
            Evt.DISCONN_COMPLETE -> if (p.size >= 6) { val handle = p.u16(3) and 0xfff
                byHandle(handle)?.let { c -> upd(c.address) { it.copy(state = ClState.IDLE, handle = -1, authenticated = false, encrypted = false,
                    error = "Disconnected: ${Assigned.err(p.u8(5))}") } }
                cidMap.clear() }
            0x06 -> byHandle(p.u16(3) and 0xfff)?.let { c -> val ok = p.u8(2) == 0
                upd(c.address) { it.copy(authenticated = ok, pairing = if (ok) "Authenticated" else "Auth failed: ${Assigned.err(p.u8(2))}") } }
            0x08 -> byHandle(p.u16(3) and 0xfff)?.let { c -> upd(c.address) { it.copy(encrypted = p.u8(2) == 0 && p.u8(5) != 0) } }
            0x0B -> if (p.size >= 13) byHandle(p.u16(3) and 0xfff)?.let { c ->
                val f = p.copyOfRange(5, 13)
                upd(c.address) { it.copy(features = Assigned.lmpFeatures.filter { (b, _) -> f.u8(b / 8) and (1 shl (b % 8)) != 0 }.toSortedMap().values.toList()) } }
            0x0C -> if (p.size >= 10) byHandle(p.u16(3) and 0xfff)?.let { c ->
                upd(c.address) { it.copy(version = "LMP ${Assigned.hciVersions[p.u8(5)] ?: "?"} · ${Assigned.company(p.u16(6))} (0x%04X) · subver 0x%04X".format(p.u16(6), p.u16(8))) } }
            0x16 -> { val a = p.addr(2); upd(a) { it.copy(pairing = "PIN code requested") }; prompt.value = PairingPrompt(PromptKind.PIN, a) }
            0x17 -> { val a = p.addr(2); val key = prefs.getString(a, null)
                launch { if (key != null) h.cmd(Op.LINK_KEY_REPLY, addrBytes(a) + key.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), check = false)
                         else h.cmd(Op.LINK_KEY_NEG, addrBytes(a), check = false) } }
            0x18 -> if (p.size >= 25) { val a = p.addr(2)
                prefs.edit().putString(a, p.copyOfRange(8, 24).hex("")).putInt("$a.type", p.u8(24)).apply()
                upd(a) { it.copy(bonded = true, keyType = p.u8(24), pairing = "Bonded (link key stored)") } }
            0x31 -> { val a = p.addr(2); upd(a) { it.copy(pairing = "SSP: IO capability exchange") }
                // DisplayYesNo, no OOB, MITM + General Bonding
                launch { h.cmd(Op.IO_CAP_REPLY, addrBytes(a) + bytesOf(0x01, 0x00, 0x05), check = false) } }
            0x32 -> if (p.size >= 9) remoteIo[p.addr(2)] = p.u8(8)
            0x33 -> if (p.size >= 12) { val a = p.addr(2); val v = p.u32(8)
                if (remoteIo[a] == 3 || remoteIo[a] == 2) { // remote NoInputNoOutput / KeyboardOnly -> Just Works style
                    upd(a) { it.copy(pairing = "SSP: Just Works") }
                    launch { h.cmd(Op.USER_CONFIRM_REPLY, addrBytes(a), check = false) }
                } else { upd(a) { it.copy(pairing = "SSP: Numeric comparison") }; prompt.value = PairingPrompt(PromptKind.CONFIRM, a, v) } }
            0x34 -> { val a = p.addr(2); upd(a) { it.copy(pairing = "SSP: Passkey entry") }; prompt.value = PairingPrompt(PromptKind.PASSKEY_ENTRY, a) }
            0x3B -> if (p.size >= 12) { val a = p.addr(2); prompt.value = PairingPrompt(PromptKind.PASSKEY_DISPLAY, a, p.u32(8)) }
            0x36 -> if (p.size >= 9) { val a = p.addr(3); val ok = p.u8(2) == 0
                if (prompt.value?.kind == PromptKind.PASSKEY_DISPLAY) prompt.value = null
                upd(a) { it.copy(pairing = if (ok) "SSP complete" else "SSP failed: ${Assigned.err(p.u8(2))}") } }
        }
    }

    // ------------ L2CAP (BR/EDR) ------------
    fun onL2cap(handle: Int, cid: Int, d: ByteArray) {
        if (cid == 1) { onSignaling(handle, d); return }
        dataWait[cid]?.complete(d)
    }

    private fun onSignaling(handle: Int, d: ByteArray) {
        var i = 0
        while (i + 4 <= d.size) {
            val code = d.u8(i); val id = d.u8(i + 1); val len = d.u16(i + 2)
            if (i + 4 + len > d.size) break
            val body = d.copyOfRange(i + 4, i + 4 + len); i += 4 + len
            val h = hci()
            when (code) {
                0x03 -> if (body.size >= 8 && body.u16(4) == 1) {} else sigWait.remove(id)?.complete(bytesOf(code) + body)
                0x01, 0x05, 0x07, 0x0B -> sigWait.remove(id)?.complete(bytesOf(code) + body)
                0x04 -> { // peer Configure Request: accept with no options
                    val local = body.u16(0); val remote = cidMap[local] ?: 0
                    h.sendL2cap(handle, 1, bytesOf(0x05, id) + le16(6) + le16(remote) + le16(0) + le16(0))
                }
                0x06 -> h.sendL2cap(handle, 1, bytesOf(0x07, id) + le16(4) + body.copyOfRange(0, 4))
                0x0A -> { val type = body.u16(0)
                    val rsp = when (type) { 2 -> le16(2) + le16(0) + bytesOf(0, 0, 0, 0); 3 -> le16(3) + le16(0) + bytesOf(0x02, 0, 0, 0, 0, 0, 0, 0); else -> le16(type) + le16(1) }
                    h.sendL2cap(handle, 1, bytesOf(0x0B, id) + le16(rsp.size) + rsp) }
                0x02 -> h.sendL2cap(handle, 1, bytesOf(0x03, id) + le16(8) + le16(0) + body.copyOfRange(2, 4) + le16(2) + le16(0)) // refuse: PSM not supported
            }
        }
    }

    private suspend fun signal(handle: Int, code: Int, body: ByteArray, timeout: Long = 8000): ByteArray {
        val id = (sigId.getAndIncrement() % 254) + 1
        val w = CompletableDeferred<ByteArray>(); sigWait[id] = w
        hci().sendL2cap(handle, 1, bytesOf(code, id) + le16(body.size) + body)
        return withTimeoutOrNull(timeout) { w.await() } ?: run { sigWait.remove(id); throw HciException("L2CAP signaling timeout") }
    }

    fun sdp(a: String) = launch {
        upd(a) { it.copy(sdpBusy = true, error = null) }
        try {
            val handle = connectNow(a)
            val local = nextCid.getAndIncrement().let { if (it > 0x00FF) { nextCid.set(0x41); 0x40 } else it }
            val r = signal(handle, 0x02, le16(0x0001) + le16(local), 15000)
            if (r.u8(0) != 0x03 || r.u16(5) != 0) throw HciException("SDP L2CAP connect refused (result ${if (r.size > 6) r.u16(5) else -1})")
            val remote = r.u16(1); cidMap[local] = remote
            val cfg = signal(handle, 0x04, le16(remote) + le16(0))
            if (cfg.u8(0) != 0x05 || cfg.u16(5) != 0) throw HciException("L2CAP configure rejected")
            delay(150)
            val lists = java.io.ByteArrayOutputStream(); var cont = byteArrayOf(0); var tid = 1
            do {
                val params = bytesOf(0x35, 0x03, 0x19, 0x01, 0x00, 0xFF, 0xFF, 0x35, 0x05, 0x0A, 0x00, 0x00, 0xFF, 0xFF) + cont
                val pdu = bytesOf(0x06, tid shr 8, tid and 0xff, params.size shr 8, params.size and 0xff) + params
                val w = CompletableDeferred<ByteArray>(); dataWait[local] = w
                hci().sendL2cap(handle, remote, pdu)
                val rsp = withTimeoutOrNull(8000) { w.await() } ?: throw HciException("SDP timeout")
                if (rsp.u8(0) == 0x01) throw HciException("SDP error response 0x%04X".format((rsp.u8(5) shl 8) or rsp.u8(6)))
                val cnt = (rsp.u8(5) shl 8) or rsp.u8(6)
                lists.write(rsp, 7, cnt)
                val cl = rsp.u8(7 + cnt); cont = rsp.copyOfRange(7 + cnt, 8 + cnt + cl); tid++
            } while (cl > 0 && tid < 50)
            dataWait.remove(local)
            runCatching { signal(handle, 0x06, le16(remote) + le16(local), 3000) }
            cidMap.remove(local)
            val recs = Sdp.records(lists.toByteArray())
            upd(a) { it.copy(sdp = recs, sdpBusy = false) }
            msg("SDP: ${recs.size} records")
        } catch (e: Exception) { upd(a) { it.copy(sdpBusy = false, error = e.message) }; throw e }
    }
}
