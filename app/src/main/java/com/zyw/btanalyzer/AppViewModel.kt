package com.zyw.btanalyzer

import android.app.Application
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.zyw.btanalyzer.hci.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.util.concurrent.ConcurrentHashMap

enum class LinkState { DISCONNECTED, CONNECTING, READY, ERROR }

data class InfoRow(val label: String, val value: String)
data class ControllerInfo(
    val rows: List<InfoRow> = emptyList(),
    val lmpFeatures: List<String> = emptyList(),
    val leFeatures: List<String> = emptyList(),
    val cloneWarning: String? = null,
    val leSupported: Boolean = true,
)

data class LeDevice(
    val address: String, val addrType: Int, val rssi: Int, val lastSeen: Long, val count: Int,
    val connectable: Boolean, val adv: ByteArray, val scanRsp: ByteArray?, val info: AdInfo, val history: List<Pair<Long, Int>>,
) {
    val name get() = info.name
    val addrTypeName get() = when (addrType) { 0 -> "Public"; 1 -> "Random"; 2 -> "Public ID"; 3 -> "Random ID"; else -> "?" }
}

data class ClassicDevice(val address: String, val rssi: Int?, val cod: Int, val name: String?, val eir: AdInfo?, val lastSeen: Long)

data class GattDesc(val handle: Int, val uuid: String, val value: ByteArray? = null)
data class GattChar(val declHandle: Int, val valueHandle: Int, val props: Int, val uuid: String,
                    val value: ByteArray? = null, val error: String? = null, val notifyCount: Int = 0,
                    val lastUpdate: Long = 0, val descs: List<GattDesc> = emptyList()) {
    val propsText get() = buildList {
        if (props and 0x02 != 0) add("R"); if (props and 0x04 != 0) add("WnR"); if (props and 0x08 != 0) add("W")
        if (props and 0x10 != 0) add("N"); if (props and 0x20 != 0) add("I"); if (props and 0x01 != 0) add("B")
    }.joinToString(" ")
}
data class GattService(val start: Int, val end: Int, val uuid: String, val chars: List<GattChar>)
enum class GattPhase { IDLE, CONNECTING, DISCOVERING, CONNECTED }
data class GattState(val phase: GattPhase = GattPhase.IDLE, val address: String? = null, val name: String? = null,
                     val handle: Int = -1, val services: List<GattService> = emptyList(), val message: String? = null, val mtu: Int = 23)

enum class SortMode { RSSI, NAME, RECENT }

class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val usb = app.getSystemService(UsbManager::class.java)
    private var transport: UsbHciTransport? = null
    private var hci: HciController? = null

    val link = MutableStateFlow(LinkState.DISCONNECTED)
    val deviceLabel = MutableStateFlow<String?>(null)
    val info = MutableStateFlow(ControllerInfo())
    val messages = MutableSharedFlow<String>(extraBufferCapacity = 16)

    // LE scan
    private val leMap = ConcurrentHashMap<String, LeDevice>()
    val leDevices = MutableStateFlow<List<LeDevice>>(emptyList())
    val scanning = MutableStateFlow(false)
    val activeScan = MutableStateFlow(true)
    // Classic
    private val clMap = ConcurrentHashMap<String, ClassicDevice>()
    val classicDevices = MutableStateFlow<List<ClassicDevice>>(emptyList())
    val inquiring = MutableStateFlow(false)
    private val nameWaiters = ConcurrentHashMap<String, CompletableDeferred<String?>>()
    val classic = ClassicManager(viewModelScope, { need() }, app.getSharedPreferences("linkkeys", 0), { msg(it) })
    // GATT
    val gatt = MutableStateFlow(GattState())
    private var connWaiter: CompletableDeferred<ByteArray>? = null
    // Log
    private val records = ArrayList<HciRecord>()
    val log = MutableStateFlow<List<HciRecord>>(emptyList())
    val logPaused = MutableStateFlow(false)
    @Volatile private var dirty = false

    init {
        viewModelScope.launch {
            while (isActive) {
                delay(400)
                if (dirty) {
                    dirty = false
                    leDevices.value = leMap.values.toList()
                    classicDevices.value = clMap.values.sortedByDescending { it.rssi ?: -127 }
                    if (!logPaused.value) log.value = synchronized(records) { records.takeLast(3000) }
                }
            }
        }
    }

    private fun msg(s: String) { messages.tryEmit(s) }

    fun findDongles(): List<UsbDevice> = usb.deviceList.values.filter { d ->
        (d.vendorId == 0x0A12 && d.productId == 0x0001) || d.deviceClass == 0xE0 ||
            (0 until d.interfaceCount).any { d.getInterface(it).let { i -> i.interfaceClass == 0xE0 && i.interfaceSubclass == 1 && i.interfaceProtocol == 1 } }
    }

    fun connect(dev: UsbDevice) {
        if (link.value == LinkState.CONNECTING || link.value == LinkState.READY) return
        if (!usb.hasPermission(dev)) { msg("USB permission missing"); return }
        link.value = LinkState.CONNECTING
        deviceLabel.value = "%04X:%04X %s".format(dev.vendorId, dev.productId, dev.productName ?: "")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                lateinit var h: HciController
                val t = UsbHciTransport(usb, dev, onEvent = { h.handleEvent(it) }, onAcl = { h.handleAcl(it) }, onError = { msg(it) })
                h = HciController(send = { type, p -> if (type == PktType.CMD) t.sendCommand(p) else t.sendAcl(p) }, log = ::addRecord)
                h.onEvent = ::onEvent
                h.onAttNotify = ::onNotify
                h.onL2cap = { hd, cid, d -> classic.onL2cap(hd, cid, d) }
                t.open(); transport = t; hci = h
                initController(h, dev)
                link.value = LinkState.READY
            } catch (e: Throwable) {
                msg("Init failed: ${e.message}")
                runCatching { transport?.close() }; transport = null; hci = null
                link.value = LinkState.ERROR
            }
        }
    }

    fun disconnectUsb() {
        scanning.value = false; inquiring.value = false
        hci?.cancelAtt(); gatt.value = GattState()
        runCatching { transport?.close() }; transport = null; hci = null
        link.value = LinkState.DISCONNECTED
    }

    fun onDetached(dev: UsbDevice) { if (transport?.device?.deviceName == dev.deviceName) { disconnectUsb(); msg("Dongle detached") } }

    private suspend fun initController(h: HciController, dev: UsbDevice) {
        // Some CSR clones need a retry for the first reset.
        try { h.cmd(Op.RESET, timeoutMs = 5000) } catch (e: Exception) { delay(300); h.cmd(Op.RESET, timeoutMs = 5000) }
        val rows = mutableListOf<InfoRow>()
        val ver = h.cmd(Op.READ_LOCAL_VERSION)
        val hciVer = ver.u8(1); val hciRev = ver.u16(2); val lmpVer = ver.u8(4); val manuf = ver.u16(5); val lmpSub = ver.u16(7)
        val addr = h.cmd(Op.READ_BD_ADDR).addr(1)
        rows += InfoRow("BD_ADDR", addr)
        rows += InfoRow("HCI Version", "${Assigned.hciVersions[hciVer] ?: "?"} (0x%02X) rev 0x%04X".format(hciVer, hciRev))
        rows += InfoRow("LMP Version", "${Assigned.hciVersions[lmpVer] ?: "?"} (0x%02X) subver 0x%04X".format(lmpVer, lmpSub))
        rows += InfoRow("Manufacturer", "%d (0x%04X) %s".format(manuf, manuf, Assigned.company(manuf)))
        rows += InfoRow("USB", "%04X:%04X bcdDevice=%s %s".format(dev.vendorId, dev.productId, dev.version, dev.manufacturerName ?: ""))
        runCatching { h.cmd(Op.READ_LOCAL_NAME) }.getOrNull()?.let { r ->
            val n = r.copyOfRange(1, r.size).takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.UTF_8)
            rows += InfoRow("Local Name", n.ifEmpty { "-" })
        }
        val feats = h.cmd(Op.READ_LOCAL_FEATURES).copyOfRange(1, 9)
        val lmp = Assigned.lmpFeatures.filter { (bit, _) -> feats.u8(bit / 8) and (1 shl (bit % 8)) != 0 }.toSortedMap().values.toList()
        rows += InfoRow("LMP Features", feats.hex())
        val leSupported = feats.u8(4) and 0x40 != 0
        runCatching { h.cmd(Op.READ_BUFFER_SIZE) }.getOrNull()?.let { r ->
            rows += InfoRow("ACL Buffers (BR/EDR)", "${r.u16(1)} B x ${r.u16(4)}  SCO ${r.u8(3)} B x ${r.u16(6)}")
            h.aclMtu = r.u16(1).coerceIn(23, 1021); h.leMtu = minOf(h.aclMtu, 251)
            h.aclCredits = java.util.concurrent.Semaphore(r.u16(4).coerceIn(1, 64))
        }
        // Event masks: enable LE Meta (bit 61) etc.
        h.cmd(Op.SET_EVENT_MASK, bytesOf(0xFF, 0xFF, 0xFB, 0xFF, 0x07, 0xF8, 0xBF, 0x3D), check = false)
        h.cmd(Op.WRITE_SSP_MODE, bytesOf(1), check = false)
        var leF = emptyList<String>()
        if (leSupported) {
            h.cmd(Op.WRITE_LE_HOST_SUPPORT, bytesOf(1, 0), check = false)
            h.cmd(Op.LE_SET_EVENT_MASK, bytesOf(0x1F, 0, 0, 0, 0, 0, 0, 0), check = false)
            runCatching { h.cmd(Op.LE_READ_BUFFER_SIZE) }.getOrNull()?.let { r ->
                val len = r.u16(1); val num = r.u8(3)
                rows += InfoRow("LE ACL Buffers", if (len == 0) "shared with BR/EDR" else "$len B x $num")
                if (len > 0) { h.leMtu = len.coerceIn(23, 251); h.leCredits = java.util.concurrent.Semaphore(num.coerceIn(1, 64)) }
            }
            runCatching { h.cmd(Op.LE_READ_FEATURES) }.getOrNull()?.let { r ->
                val f = r.copyOfRange(1, 9)
                rows += InfoRow("LE Features", f.hex())
                leF = Assigned.leFeatures.filter { (bit, _) -> f.u8(bit / 8) and (1 shl (bit % 8)) != 0 }.values.toList()
            }
            runCatching { h.cmd(Op.LE_READ_WHITE_LIST_SIZE) }.getOrNull()?.let { rows += InfoRow("LE White List", "${it.u8(1)}") }
            runCatching { h.cmd(Op.LE_READ_SUPPORTED_STATES) }.getOrNull()?.let { rows += InfoRow("LE States", it.copyOfRange(1, 9).hex()) }
        }
        // Clone heuristic (mirrors Linux btusb CSR checks loosely)
        val bcd = dev.version.replace(".", "").toIntOrNull(16) ?: -1
        val warn = when {
            dev.vendorId == 0x0A12 && manuf != 10 -> "Manufacturer ID is $manuf, not 10 (CSR) → likely a clone chip"
            dev.vendorId == 0x0A12 && hciRev == lmpSub && bcd in listOf(0x0134, 0x1915, 0x2520, 0x7558, 0x8891) -> "bcdDevice 0x%04X matches known clone revisions (Linux btusb list)".format(bcd)
            dev.vendorId == 0x0A12 && hciVer < 6 -> "Reports HCI < 4.0 → possibly a fake/old chip; LE may not work"
            else -> null
        }
        info.value = ControllerInfo(rows, lmp, leF, warn, leSupported)
        msg("Controller ready: $addr")
    }

    private fun need(): HciController = hci ?: throw HciException("Dongle not connected")

    private fun launchSafe(block: suspend CoroutineScope.() -> Unit) = viewModelScope.launch(Dispatchers.IO) {
        try { block() } catch (e: CancellationException) { throw e } catch (e: Throwable) { msg(e.message ?: e.toString()) }
    }

    // ---------------- LE scan ----------------
    fun toggleScan() = launchSafe {
        val h = need()
        if (scanning.value) { h.cmd(Op.LE_SET_SCAN_ENABLE, bytesOf(0, 0), check = false); scanning.value = false; return@launchSafe }
        h.cmd(Op.LE_SET_SCAN_ENABLE, bytesOf(0, 0), check = false)
        h.cmd(Op.LE_SET_SCAN_PARAMS, bytesOf(if (activeScan.value) 1 else 0, 0x30, 0, 0x30, 0, 0, 0))
        h.cmd(Op.LE_SET_SCAN_ENABLE, bytesOf(1, 0)) // no duplicate filtering -> continuous RSSI
        scanning.value = true
    }
    fun clearLe() { leMap.clear(); dirty = true }

    private fun onAdvReport(p: ByteArray) {
        var i = 3; val num = p.u8(3); i++
        repeat(num) {
            if (i + 9 > p.size) return
            val evType = p.u8(i); val at = p.u8(i + 1); val addr = p.addr(i + 2); val len = p.u8(i + 8)
            if (i + 9 + len + 1 > p.size) return
            val data = p.copyOfRange(i + 9, i + 9 + len); val rssi = p.s8(i + 9 + len)
            i += 10 + len
            val now = System.currentTimeMillis(); val old = leMap[addr]
            val isRsp = evType == 4
            val adv = if (isRsp) old?.adv ?: ByteArray(0) else data
            val rsp = if (isRsp) data else old?.scanRsp
            val hist = ((old?.history ?: emptyList()) + (now to rssi)).takeLast(120)
            leMap[addr] = LeDevice(addr, at, rssi, now, (old?.count ?: 0) + 1,
                if (isRsp) old?.connectable ?: true else evType == 0 || evType == 1, adv, rsp,
                if (old != null && old.adv.contentEquals(adv) && old.scanRsp.contentEqualsNullable(rsp)) old.info else AdParser.parse(adv + (rsp ?: ByteArray(0))),
                hist)
            dirty = true
        }
    }
    private fun ByteArray?.contentEqualsNullable(o: ByteArray?) = if (this == null) o == null else o != null && contentEquals(o)

    // ---------------- Classic inquiry ----------------
    fun toggleInquiry() = launchSafe {
        val h = need()
        if (inquiring.value) { h.cmd(Op.INQUIRY_CANCEL, check = false); inquiring.value = false; return@launchSafe }
        if (h.cmd(Op.WRITE_INQUIRY_MODE, bytesOf(2), check = false).u8(0) != 0) h.cmd(Op.WRITE_INQUIRY_MODE, bytesOf(1), check = false)
        h.cmd(Op.INQUIRY, bytesOf(0x33, 0x8B, 0x9E, 0x08, 0x00))
        inquiring.value = true
    }
    fun clearClassic() { clMap.clear(); dirty = true }

    private fun putClassic(addr: String, rssi: Int?, cod: Int, eir: ByteArray?) {
        val old = clMap[addr]; val ad = eir?.let { AdParser.parse(it) }
        classic.ensure(addr)
        clMap[addr] = ClassicDevice(addr, rssi ?: old?.rssi, cod, ad?.name ?: old?.name, ad ?: old?.eir, System.currentTimeMillis())
        dirty = true
    }

    private fun resolveNames() = launchSafe {
        val h = need()
        for (d in clMap.values.filter { it.name == null }) {
            val w = CompletableDeferred<String?>(); nameWaiters[d.address] = w
            try {
                h.cmd(Op.REMOTE_NAME, addrBytes(d.address) + bytesOf(1, 0, 0, 0))
                val n = withTimeoutOrNull(12000) { w.await() }
                if (n == null) h.cmd(Op.REMOTE_NAME_CANCEL, addrBytes(d.address), check = false)
                else clMap[d.address]?.let { clMap[d.address] = it.copy(name = n) }
                dirty = true
            } catch (e: Exception) { msg("Name ${d.address}: ${e.message}") } finally { nameWaiters.remove(d.address) }
        }
    }

    // ---------------- GATT ----------------
    fun connectGatt(d: LeDevice) = launchSafe {
        val h = need()
        if (gatt.value.phase != GattPhase.IDLE) { msg("Already connected/connecting"); return@launchSafe }
        if (scanning.value) { h.cmd(Op.LE_SET_SCAN_ENABLE, bytesOf(0, 0), check = false); scanning.value = false }
        gatt.value = GattState(GattPhase.CONNECTING, d.address, d.name)
        val w = CompletableDeferred<ByteArray>(); connWaiter = w
        h.cmd(Op.LE_CREATE_CONN, bytesOf(0x60, 0, 0x30, 0, 0, d.addrType and 1) + addrBytes(d.address) +
            bytesOf(0, 0x18, 0, 0x28, 0, 0, 0, 0xF4, 0x01, 0, 0, 0, 0))
        val ev = withTimeoutOrNull(10000) { w.await() }
        if (ev == null) {
            h.cmd(Op.LE_CREATE_CONN_CANCEL, check = false)
            gatt.value = GattState(message = "Connection timeout"); msg("Connection timeout"); return@launchSafe
        }
        val status = ev.u8(3)
        if (status != 0) { gatt.value = GattState(message = Assigned.err(status)); msg("Connect failed: ${Assigned.err(status)}"); return@launchSafe }
        val handle = ev.u16(4) and 0xfff
        h.linkIsLe[handle] = true; h.attMtu = 23
        h.attHandle = handle
        gatt.value = gatt.value.copy(phase = GattPhase.DISCOVERING, handle = handle)
        try { discover(h) } catch (e: Exception) { msg("Discovery: ${e.message}") }
        if (gatt.value.handle == handle) gatt.value = gatt.value.copy(phase = GattPhase.CONNECTED)
    }

    private suspend fun discover(h: HciController) {
        val services = mutableListOf<GattService>()
        var start = 1
        while (start <= 0xFFFF) {
            val r = try { h.att(bytesOf(0x10) + le16(start) + le16(0xFFFF) + le16(0x2800), 0x11) } catch (e: AttError) { if (e.code == 0x0A) break else throw e }
            val len = r.u8(1); var i = 2; var last = start
            while (i + len <= r.size) {
                val s = r.u16(i); val e = r.u16(i + 2); val u = uuidString(r.copyOfRange(i + 4, i + len))
                services += GattService(s, e, u, emptyList()); last = e; i += len
            }
            if (last >= 0xFFFF || last < start) break
            start = last + 1
        }
        gatt.value = gatt.value.copy(services = services.toList())
        for ((idx, svc) in services.withIndex()) {
            val chars = mutableListOf<GattChar>(); var s = svc.start
            while (s <= svc.end) {
                val r = try { h.att(bytesOf(0x08) + le16(s) + le16(svc.end) + le16(0x2803), 0x09) } catch (e: AttError) { if (e.code == 0x0A) break else throw e }
                val len = r.u8(1); var i = 2; var last = s
                while (i + len <= r.size) {
                    val decl = r.u16(i); val props = r.u8(i + 2); val vh = r.u16(i + 3)
                    chars += GattChar(decl, vh, props, uuidString(r.copyOfRange(i + 5, i + len))); last = decl; i += len
                }
                if (last < s) break
                s = last + 1
            }
            for ((ci, c) in chars.withIndex()) {
                val end = if (ci + 1 < chars.size) chars[ci + 1].declHandle - 1 else svc.end
                var st = c.valueHandle + 1; val descs = mutableListOf<GattDesc>()
                while (st <= end) {
                    val r = try { h.att(bytesOf(0x04) + le16(st) + le16(end), 0x05) } catch (e: AttError) { break }
                    val w = if (r.u8(1) == 1) 4 else 18; var i = 2; var last = st
                    while (i + w <= r.size) { val dh = r.u16(i); descs += GattDesc(dh, uuidString(r.copyOfRange(i + 2, i + w))); last = dh; i += w }
                    if (last < st) break
                    st = last + 1
                }
                chars[ci] = c.copy(descs = descs)
            }
            services[idx] = svc.copy(chars = chars)
            gatt.value = gatt.value.copy(services = services.toList())
        }
    }

    fun readChar(c: GattChar) = launchSafe {
        val h = need()
        val res = try {
            val r = h.att(bytesOf(0x0A) + le16(c.valueHandle), 0x0B)
            var v = r.copyOfRange(1, r.size)
            // long value -> Read Blob
            while (v.size >= h.attMtu - 1 && v.size < 512) {
                val b = try { h.att(bytesOf(0x0C) + le16(c.valueHandle) + le16(v.size), 0x0D) } catch (e: AttError) { break }
                if (b.size <= 1) break
                v += b.copyOfRange(1, b.size); if (b.size < h.attMtu) break
            }
            c.copy(value = v, error = null)
        } catch (e: Exception) { c.copy(error = e.message) }
        updateChar(res)
    }

    fun subscribe(c: GattChar) = launchSafe {
        val h = need()
        val v = if (c.props and 0x10 != 0) 1 else 2
        val cccd = c.descs.firstOrNull { Assigned.short16(it.uuid) == 0x2902 }?.handle ?: run { msg("CCCD not found"); return@launchSafe }
        val on = c.notifyCount >= 0 && !(c.descs.first { it.handle == cccd }.value?.let { it.isNotEmpty() && it[0].toInt() != 0 } ?: false)
        h.att(bytesOf(0x12) + le16(cccd) + le16(if (on) v else 0), 0x13)
        updateDesc(cccd, le16(if (on) v else 0))
        msg((if (on) "Subscribed" else "Unsubscribed") + " 0x%04X".format(c.valueHandle))
    }

    /** Write a characteristic value or descriptor. withResponse=false -> Write Command. */
    fun writeAttr(handle: Int, value: ByteArray, withResponse: Boolean) = launchSafe {
        val h = need()
        if (value.size > h.attMtu - 3) throw HciException("Value too long for MTU ${h.attMtu} (max ${h.attMtu - 3} bytes)")
        if (withResponse) h.att(bytesOf(0x12) + le16(handle) + value, 0x13) else h.attCmd(bytesOf(0x52) + le16(handle) + value)
        updateDesc(handle, value)
        val g = gatt.value
        gatt.value = g.copy(services = g.services.map { s -> s.copy(chars = s.chars.map { if (it.valueHandle == handle) it.copy(value = value, error = null) else it }) })
        msg("Wrote ${value.size} B to 0x%04X".format(handle))
    }
    fun readDesc(handle: Int) = launchSafe {
        val r = need().att(bytesOf(0x0A) + le16(handle), 0x0B); updateDesc(handle, r.copyOfRange(1, r.size))
    }
    fun exchangeMtu(mtu: Int = 247) = launchSafe {
        val h = need()
        val r = h.att(bytesOf(0x02) + le16(mtu), 0x03)
        h.attMtu = minOf(mtu, r.u16(1)).coerceAtLeast(23)
        gatt.value = gatt.value.copy(mtu = h.attMtu); msg("ATT MTU = ${h.attMtu}")
    }
    private fun updateDesc(handle: Int, v: ByteArray) {
        val g = gatt.value
        gatt.value = g.copy(services = g.services.map { s -> s.copy(chars = s.chars.map { c -> c.copy(descs = c.descs.map { if (it.handle == handle) it.copy(value = v) else it }) }) })
    }
    /** All captured packets belonging to the current LE connection. */
    fun connectionPackets(): List<HciRecord> {
        val hd = gatt.value.handle
        return synchronized(records) { records.filter { HciController.aclHandle(it.type, it.data) == hd } }
    }
    fun exportRecords(uri: Uri, recs: List<HciRecord>) = launchSafe {
        getApplication<Application>().contentResolver.openOutputStream(uri)?.use { BtSnoop.write(it, recs) } ?: throw java.io.IOException("Cannot open output")
        msg("Exported ${recs.size} packets")
    }

    private fun updateChar(c: GattChar) {
        val g = gatt.value
        gatt.value = g.copy(services = g.services.map { s -> s.copy(chars = s.chars.map { if (it.valueHandle == c.valueHandle) c else it }) })
    }

    private fun onNotify(handle: Int, value: ByteArray, ind: Boolean) {
        val g = gatt.value
        gatt.value = g.copy(services = g.services.map { s -> s.copy(chars = s.chars.map { if (it.valueHandle == handle) it.copy(value = value, notifyCount = it.notifyCount + 1, error = null, lastUpdate = System.currentTimeMillis()) else it }) })
    }

    fun disconnectGatt() = launchSafe {
        val h = need(); val g = gatt.value
        when (g.phase) {
            GattPhase.CONNECTING -> { h.cmd(Op.LE_CREATE_CONN_CANCEL, check = false); connWaiter?.complete(bytesOf(0x3E, 0, 1, 0x02)) }
            GattPhase.IDLE -> {}
            else -> h.cmd(Op.DISCONNECT, le16(g.handle) + bytesOf(0x13), check = false)
        }
    }

    // ---------------- events ----------------
    private fun onEvent(p: ByteArray) {
        runCatching { classic.onEvent(p) }.onFailure { msg("Classic: ${it.message}") }
        if (p.u8(0) == Evt.DISCONN_COMPLETE && p.size >= 6) hci?.linkClosed(p.u16(3) and 0xfff)
        when (p.u8(0)) {
            Evt.LE_META -> when (p.u8(2)) {
                2 -> onAdvReport(p)
                1 -> connWaiter?.let { connWaiter = null; it.complete(p) }
            }
            Evt.INQUIRY_RESULT -> if (p.size >= 17) putClassic(p.addr(3), null, p.u24(12), null)
            Evt.INQUIRY_RESULT_RSSI -> if (p.size >= 17) putClassic(p.addr(3), p.s8(16), p.u24(11), null)
            Evt.EXT_INQUIRY_RESULT -> if (p.size >= 17) putClassic(p.addr(3), p.s8(16), p.u24(11), p.copyOfRange(17, p.size))
            Evt.INQUIRY_COMPLETE -> { if (inquiring.value) { inquiring.value = false; resolveNames() } }
            Evt.REMOTE_NAME -> if (p.size >= 9) {
                val a = p.addr(3)
                val n = if (p.u8(2) == 0) p.copyOfRange(9, p.size).takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.UTF_8) else null
                nameWaiters[a]?.complete(n)
            }
            Evt.DISCONN_COMPLETE -> if (p.size >= 6 && (p.u16(3) and 0xfff) == gatt.value.handle) {
                hci?.attHandle = -1; hci?.cancelAtt()
                gatt.value = gatt.value.copy(phase = GattPhase.IDLE, handle = -1, mtu = 23, message = "Disconnected: ${Assigned.err(p.u8(5))}")
            }
            Evt.HW_ERROR -> msg("Controller hardware error 0x%02X".format(p.u8(2)))
        }
    }

    // ---------------- log ----------------
    private fun addRecord(r: HciRecord) {
        synchronized(records) { records.add(r); if (records.size > 100_000) records.subList(0, 20_000).clear() }
        dirty = true
    }
    fun clearLog() { synchronized(records) { records.clear() }; log.value = emptyList() }
    fun togglePause() { logPaused.value = !logPaused.value; dirty = true }

    fun exportBtsnoop(uri: Uri) = launchSafe {
        val snap = synchronized(records) { records.toList() }
        getApplication<Application>().contentResolver.openOutputStream(uri)?.use { BtSnoop.write(it, snap) }
            ?: throw java.io.IOException("Cannot open output")
        msg("Exported ${snap.size} packets")
    }

    // ---------------- Phone built-in BT log (root) ----------------
    val sysProbe = MutableStateFlow<SystemSnoop.Probe?>(null)
    val sysProbing = MutableStateFlow(false)
    val sysPath = MutableStateFlow<String?>(null)
    val sysTailing = MutableStateFlow(false)
    val sysLog = MutableStateFlow<List<HciRecord>>(emptyList())
    val sysPaused = MutableStateFlow(false)
    private val sysRecords = ArrayList<HciRecord>()
    private var tailer: SystemSnoop.Tailer? = null
    @Volatile private var sysDirty = false

    fun probeSystem() = launchSafe {
        sysProbing.value = true
        try {
            val p = SystemSnoop.probe(); sysProbe.value = p
            if (sysPath.value == null) sysPath.value = (p.files.firstOrNull { !it.path.endsWith(".last") } ?: p.files.firstOrNull())?.path
        } finally { sysProbing.value = false }
    }
    fun selectSysPath(p: String) { sysPath.value = p }
    val sysViewer = MutableStateFlow<SystemSnoop.SnoopFile?>(null)
    val sysProgress = MutableStateFlow(0f)
    val sysFollow = MutableStateFlow(false)
    fun openSysFile(f: SystemSnoop.SnoopFile, follow: Boolean) {
        tailer?.stop(); tailer = null
        sysPath.value = f.path; sysViewer.value = f; sysFollow.value = follow; clearSys(); sysProgress.value = 0f
        val t = SystemSnoop.Tailer(f.path, fromEnd = false, follow = follow, onRecord = { r ->
            synchronized(sysRecords) { sysRecords.add(r); if (sysRecords.size > 400_000) sysRecords.subList(0, 50_000).clear() }
            sysDirty = true
        }, onStatus = ::msg)
        tailer = t; sysTailing.value = true
        viewModelScope.launch(Dispatchers.IO) { t.run(); if (tailer === t) { sysTailing.value = false; sysDirty = true } }
        viewModelScope.launch {
            while (tailer === t) {
                delay(400)
                sysProgress.value = if (f.size > 0) (t.bytesRead.toFloat() / f.size).coerceAtMost(1f) else 0f
                if (sysDirty && !sysPaused.value) { sysDirty = false; sysLog.value = synchronized(sysRecords) { sysRecords.toList() } }
                if (!t.running && !sysDirty) { sysProgress.value = 1f; break }
            }
        }
    }
    fun closeSysViewer() { tailer?.stop(); tailer = null; sysTailing.value = false; sysViewer.value = null }

    fun clearSys() { synchronized(sysRecords) { sysRecords.clear() }; sysLog.value = emptyList() }
    fun toggleSysPause() { sysPaused.value = !sysPaused.value; sysDirty = true }
    fun exportSys(uri: Uri) = launchSafe {
        val path = sysPath.value ?: throw java.io.IOException("No log file")
        // read-only: copy into app-private storage first, then save the copy where the user chose
        val app = getApplication<Application>()
        val local = java.io.File(app.filesDir, "phone_btsnoop_${System.currentTimeMillis()}.log")
        local.outputStream().use { SystemSnoop.copyTo(path, it) }
        if (local.length() == 0L) throw java.io.IOException("Copy empty (root denied?)")
        app.contentResolver.openOutputStream(uri)?.use { o -> local.inputStream().use { it.copyTo(o) } }
        msg("Exported ${local.length()} bytes (copy kept in app storage)")
    }

    override fun onCleared() { tailer?.stop(); runCatching { transport?.close() } }
}
