package com.zyw.btanalyzer.hci

import java.io.DataInputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit

/** STRICTLY READ-ONLY root access (only id/stat/getprop/cat/tail are ever run) to the phone's own Bluetooth stack btsnoop log. */
object SystemSnoop {
    val candidates = listOf(
        "/data/misc/bluetooth/logs/btsnoop_hci.log", "/data/misc/bluetooth/logs/btsnoop_hci.log.last",
        "/data/log/bt/btsnoop_hci.log", "/data/vendor/bluetooth/btsnoop_hci.log", "/data/vendor/bt/btsnoop_hci.log",
        "/data/misc/bluedroid/btsnoop_hci.log", "/sdcard/btsnoop_hci.log", "/sdcard/MIUI/debug_log/btsnoop_hci.log",
    )
    /** Directories searched (read-only) for any *snoop* file. */
    val dirs = listOf("/data/misc/bluetooth/logs", "/data/misc/bluetooth", "/data/log/bt", "/data/vendor/bluetooth",
        "/data/vendor/bt", "/data/misc/bluedroid", "/sdcard/MIUI/debug_log", "/data/user_de/0/com.android.bluetooth",
        "/data/user_de/0/com.google.android.bluetooth", "/sdcard")

    data class SnoopFile(val path: String, val size: Long, val mtime: Long)
    data class Probe(val root: Boolean, val files: List<SnoopFile>, val mode: String, val diag: List<String>)

    fun su(cmd: String, timeoutS: Long = 8): String? = try {
        val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        if (!p.waitFor(timeoutS, TimeUnit.SECONDS)) { p.destroy(); null } else if (p.exitValue() == 0) out else out.ifEmpty { null }
    } catch (e: Exception) { null }

    fun probe(): Probe {
        val id = su("id") ?: return Probe(false, emptyList(), "", listOf("su -c id: failed / denied"))
        if (!id.contains("uid=0")) return Probe(false, emptyList(), "", listOf("su -c id: $id"))
        val diag = mutableListOf("su: ${id.trim().take(60)}")
        val props = listOf("persist.bluetooth.btsnooplogmode", "persist.bluetooth.btsnoopenable", "persist.bluetooth.btsnooppath",
            "persist.bluetooth.btsnoopdefaultmode", "persist.vendor.bluetooth.btsnoop", "ro.product.brand")
        val pv = props.associateWith { (su("getprop $it")?.trim() ?: "") }
        pv.forEach { (k, v) -> diag += "getprop $k = ${v.ifEmpty { "(empty)" }}" }
        val mode = pv["persist.bluetooth.btsnooplogmode"]!!.ifEmpty { pv["persist.bluetooth.btsnoopenable"]!!.ifEmpty { "(unset)" } }
        // bt_stack.conf (read-only)
        val extra = mutableListOf<String>()
        pv["persist.bluetooth.btsnooppath"]?.takeIf { it.startsWith("/") }?.let { extra += it }
        for (conf in listOf("/etc/bluetooth/bt_stack.conf", "/system/etc/bluetooth/bt_stack.conf", "/vendor/etc/bluetooth/bt_stack.conf")) {
            val txt = su("cat '$conf' 2>/dev/null") ?: continue
            txt.lines().map { it.trim() }.filter { !it.startsWith("#") && (it.startsWith("BtSnoop") || it.startsWith("TraceConf")) }.forEach { line ->
                diag += "$conf: $line"
                if (line.startsWith("BtSnoopFileName")) line.substringAfter("=").trim().takeIf { it.startsWith("/") }?.let { extra += it }
            }
        }
        val fmt = "F|%s|%Y|%n"
        val list = (candidates + extra).distinct().joinToString(" ") { "'$it'" }
        val script = "for p in $list; do [ -f \"\$p\" ] && stat -c '$fmt' \"\$p\"; done; " +
            "find ${dirs.joinToString(" ") { "'$it'" }} -maxdepth 3 -type f -iname '*snoop*' -exec stat -c '$fmt' {} + 2>/dev/null; " +
            "find /data /sdcard /storage/emulated/0 -maxdepth 6 -type f -iname '*btsnoop*' -exec stat -c '$fmt' {} + 2>/dev/null"
        val out = su(script, 40) ?: ""
        val files = out.lines().filter { it.startsWith("F|") }.mapNotNull {
            val p = it.split("|", limit = 4); if (p.size < 4) null else SnoopFile(p[3], p[1].toLongOrNull() ?: 0, (p[2].toLongOrNull() ?: 0) * 1000)
        }.distinctBy { it.path.replace("/storage/emulated/0", "/sdcard") }.sortedByDescending { it.mtime }
        diag += "checked paths: " + (candidates + extra).distinct().joinToString(", ")
        diag += "searched dirs (depth 3): " + dirs.joinToString(", ")
        diag += "find /data /sdcard /storage/emulated/0 -maxdepth 6 -iname '*btsnoop*' → ${files.size} file(s)"
        files.forEach { diag += "  ${it.path}  ${it.size} B" }
        return Probe(true, files, mode, diag)
    }

    fun copyTo(path: String, out: OutputStream) {
        val p = ProcessBuilder("su", "-c", "cat '$path'").start()
        p.inputStream.use { it.copyTo(out) }
        p.waitFor(10, TimeUnit.SECONDS)
    }

    /**
     * Live tail: `tail -c +1 -F` streams the whole file then follows (handles rotation).
     * [fromEnd] skips existing content (start at current end).
     */
    class Tailer(private val path: String, private val fromEnd: Boolean, private val follow: Boolean = true, private val onRecord: (HciRecord) -> Unit,
                 private val onStatus: (String) -> Unit) {
        @Volatile private var proc: Process? = null
        @Volatile var running = false; private set
        private var id = 0L
        @Volatile var bytesRead = 0L; private set

        fun run() {
            running = true
            try {
                val cmd = when { fromEnd -> "tail -c 0 -F '$path'"; follow -> "tail -c +1 -F '$path'"; else -> "cat '$path'" }
                val p = ProcessBuilder("su", "-c", cmd).start(); proc = p
                val counting = object : java.io.FilterInputStream(p.inputStream.buffered(64 * 1024)) {
                    override fun read(): Int = super.read().also { if (it >= 0) bytesRead++ }
                    override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, len).also { if (it > 0) bytesRead += it }
                }
                parse(DataInputStream(counting), skipHeader = !fromEnd)
            } catch (e: EOFException) {
            } catch (e: Exception) { if (running) onStatus("Tail error: ${e.message}") }
            finally { running = false; proc?.destroy() }
        }

        private fun parse(d: DataInputStream, skipHeader: Boolean) {
            if (skipHeader) { val h = ByteArray(16); d.readFully(h); if (String(h, 0, 7) != "btsnoop") onStatus("Not a btsnoop file?") }
            val hdr = ByteArray(24)
            while (running) {
                d.readFully(hdr)
                if (String(hdr, 0, 7, Charsets.ISO_8859_1) == "btsnoop") { // file rotated: 16B file header inside stream
                    System.arraycopy(hdr, 16, hdr, 0, 8); d.readFully(hdr, 8, 16)
                }
                val incl = be32(hdr, 4); val flags = be32(hdr, 8)
                val tsUs = be64(hdr, 16)
                if (incl <= 0 || incl > 70000) { onStatus("Stream out of sync, resyncing…"); resync(d); continue }
                val data = ByteArray(incl); d.readFully(data)
                val type = when (data[0].toInt()) { 1 -> PktType.CMD; 2 -> PktType.ACL; 4 -> PktType.EVT; else -> null } ?: continue
                val payload = data.copyOfRange(1, data.size)
                val ms = (tsUs - 0x00dcddb30f2f8000L) / 1000
                val sent = flags and 1 == 0
                onRecord(HciRecord(++id, ms, sent, type, payload, HciController.summarize(type, payload)))
            }
        }

        /** Scan forward for a plausible record header (rare; only after rotation glitches). */
        private fun resync(d: DataInputStream) {
            val w = ArrayDeque<Int>()
            while (running) {
                w.addLast(d.readUnsignedByte()); if (w.size > 8) w.removeFirst()
                if (w.size == 8) {
                    val a = w.toList()
                    val o = (a[0] shl 24) or (a[1] shl 16) or (a[2] shl 8) or a[3]
                    val i = (a[4] shl 24) or (a[5] shl 16) or (a[6] shl 8) or a[7]
                    if (o == i && o in 2..1100) { d.readFully(ByteArray(16)); val data = ByteArray(i); d.readFully(data); return }
                }
            }
        }

        fun stop() { running = false; proc?.destroy() }

        private fun be32(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 24) or ((b[o + 1].toInt() and 0xff) shl 16) or
            ((b[o + 2].toInt() and 0xff) shl 8) or (b[o + 3].toInt() and 0xff)
        private fun be64(b: ByteArray, o: Int) = (be32(b, o).toLong() shl 32) or (be32(b, o + 4).toLong() and 0xffffffffL)
    }
}
