package com.zyw.btanalyzer.hci

import android.hardware.usb.*
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlin.concurrent.thread

/**
 * Raw HCI over USB (Bluetooth Core spec Vol 4 Part B):
 *  - HCI commands: control transfer, bmRequestType=0x20 (class, interface), bRequest=0
 *  - HCI events: interrupt IN endpoint (usually 0x81)
 *  - ACL data: bulk IN (0x82) / bulk OUT (0x02)
 */
class UsbHciTransport(
    private val manager: UsbManager,
    val device: UsbDevice,
    private val onEvent: (ByteArray) -> Unit,
    private val onAcl: (ByteArray) -> Unit,
    private val onError: (String) -> Unit,
) {
    private var conn: UsbDeviceConnection? = null
    private var iface: UsbInterface? = null
    private var epEvt: UsbEndpoint? = null
    private var epAclIn: UsbEndpoint? = null
    private var epAclOut: UsbEndpoint? = null
    @Volatile private var running = false
    private val threads = mutableListOf<Thread>()

    fun open() {
        // Interface 0 of a BT controller carries the interrupt + bulk endpoints.
        val itf = (0 until device.interfaceCount).map { device.getInterface(it) }.firstOrNull { i ->
            (0 until i.endpointCount).any { i.getEndpoint(it).type == UsbConstants.USB_ENDPOINT_XFER_INT }
        } ?: throw IOException("No HCI interface (interrupt endpoint) found")
        for (k in 0 until itf.endpointCount) {
            val e = itf.getEndpoint(k)
            when {
                e.type == UsbConstants.USB_ENDPOINT_XFER_INT && e.direction == UsbConstants.USB_DIR_IN -> epEvt = e
                e.type == UsbConstants.USB_ENDPOINT_XFER_BULK && e.direction == UsbConstants.USB_DIR_IN -> epAclIn = e
                e.type == UsbConstants.USB_ENDPOINT_XFER_BULK && e.direction == UsbConstants.USB_DIR_OUT -> epAclOut = e
            }
        }
        if (epEvt == null) throw IOException("Event endpoint missing")
        val c = manager.openDevice(device) ?: throw IOException("openDevice failed (permission?)")
        if (!c.claimInterface(itf, true)) { c.close(); throw IOException("claimInterface failed (kernel driver busy?)") }
        conn = c; iface = itf; running = true
        threads += thread(name = "hci-evt", isDaemon = true) { eventLoop() }
        if (epAclIn != null) threads += thread(name = "hci-acl", isDaemon = true) { aclLoop() }
    }

    private fun eventLoop() {
        val ep = epEvt!!; val buf = ByteArray(maxOf(ep.maxPacketSize, 64))
        val acc = ByteArrayOutputStream()
        while (running) {
            val n = conn?.bulkTransfer(ep, buf, buf.size, 500) ?: break
            if (n <= 0) { if (n < 0 && !running) break; continue }
            acc.write(buf, 0, n)
            // reassemble: event header = code(1) + len(1)
            while (true) {
                val a = acc.toByteArray()
                if (a.size < 2) break
                val total = 2 + (a[1].toInt() and 0xff)
                if (a.size < total) break
                val pkt = a.copyOfRange(0, total)
                acc.reset(); acc.write(a, total, a.size - total)
                try { onEvent(pkt) } catch (t: Throwable) { Log.e(TAG, "evt handler", t) }
            }
        }
    }

    private fun aclLoop() {
        val ep = epAclIn!!; val buf = ByteArray(4096)
        val acc = ByteArrayOutputStream()
        while (running) {
            val n = conn?.bulkTransfer(ep, buf, buf.size, 500) ?: break
            if (n <= 0) continue
            acc.write(buf, 0, n)
            while (true) {
                val a = acc.toByteArray()
                if (a.size < 4) break
                val total = 4 + ((a[2].toInt() and 0xff) or ((a[3].toInt() and 0xff) shl 8))
                if (a.size < total) break
                val pkt = a.copyOfRange(0, total)
                acc.reset(); acc.write(a, total, a.size - total)
                try { onAcl(pkt) } catch (t: Throwable) { Log.e(TAG, "acl handler", t) }
            }
        }
    }

    fun sendCommand(pkt: ByteArray) {
        val c = conn ?: throw IOException("Not open")
        val r = c.controlTransfer(0x20, 0, 0, iface?.id ?: 0, pkt, pkt.size, 1000)
        if (r < 0) { onError("controlTransfer failed ($r)"); throw IOException("HCI command transfer failed") }
    }

    fun sendAcl(pkt: ByteArray) {
        val c = conn ?: throw IOException("Not open")
        val ep = epAclOut ?: throw IOException("No ACL OUT endpoint")
        val r = c.bulkTransfer(ep, pkt, pkt.size, 1000)
        if (r < 0) throw IOException("ACL bulk transfer failed")
    }

    fun close() {
        running = false
        threads.forEach { runCatching { it.join(800) } }; threads.clear()
        runCatching { iface?.let { conn?.releaseInterface(it) } }
        runCatching { conn?.close() }
        conn = null
    }

    companion object { const val TAG = "UsbHci" }
}
