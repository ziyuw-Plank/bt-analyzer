package com.zyw.btanalyzer.ui

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.zyw.btanalyzer.*
import com.zyw.btanalyzer.R
import com.zyw.btanalyzer.hci.*
import java.text.SimpleDateFormat
import java.util.*

private val fileTs get() = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())

// ======================= Packet list (shared) =======================
private val CATS = listOf("CMD", "EVT", "ATT", "L2CAP", "SMP", "ACL")

private fun matchesTarget(r: HciRecord, q: String): Boolean {
    val t = q.trim(); if (t.isEmpty()) return true
    val hx = t.removePrefix("0x").removePrefix("0X")
    if (hx.length in 1..3 && hx.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return HciController.aclHandle(r.type, r.data) == hx.toInt(16)
    if (t.count { it == ':' } == 5) return runCatching { val a = addrBytes(t.uppercase()); r.data.toList().windowed(6).any { it.toByteArray().contentEquals(a) } }.getOrDefault(false)
    return false
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun PacketList(records: List<HciRecord>, paused: Boolean, autoScroll: Boolean = true) {
    var cats by rememberSaveable { mutableStateOf(setOf<String>()) }
    var q by rememberSaveable { mutableStateOf("") }
    var target by rememberSaveable { mutableStateOf("") }
    var detail by remember { mutableStateOf<HciRecord?>(null) }
    val shown = remember(records, cats, q, target) {
        records.filter { r -> (cats.isEmpty() || HciController.category(r.type, r.data) in cats) && (q.isBlank() || r.summary.contains(q, true)) && matchesTarget(r, target) }
    }
    val st = rememberLazyListState()
    LaunchedEffect(shown.size) { if (autoScroll && !paused && shown.isNotEmpty() && st.firstVisibleItemIndex + 30 >= shown.size - 5) st.scrollToItem(shown.size - 1) }
    Column {
        FlowRow(Modifier.padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            FilterChip(cats.isEmpty(), { cats = emptySet() }, { Text(stringResource(R.string.all)) })
            CATS.forEach { c -> FilterChip(c in cats, { cats = if (c in cats) cats - c else cats + c }, { Text(if (c == "ATT") "ATT/GATT" else c) }) }
        }
        Row(Modifier.padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(q, { q = it }, Modifier.weight(1f), singleLine = true, label = { Text(stringResource(R.string.search)) })
            OutlinedTextField(target, { target = it }, Modifier.weight(1f), singleLine = true, label = { Text(stringResource(R.string.handle_or_addr)) })
        }
        Text(stringResource(R.string.packets_shown, shown.size, records.size), style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
        val tx = stringResource(R.string.sent); val rx = stringResource(R.string.received)
        if (shown.isEmpty()) EmptyHint(stringResource(R.string.log_empty))
        LazyColumn(state = st) { items(shown, key = { it.id }) { r -> PacketRow(r, tx, rx) { detail = r }; HorizontalDivider() } }
    }
    detail?.let { PacketDetailSheet(it) { detail = null } }
}

@Composable
fun LogScreen(vm: AppViewModel) {
    val recs by vm.log.collectAsStateWithLifecycle()
    val paused by vm.logPaused.collectAsStateWithLifecycle()
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { it?.let(vm::exportBtsnoop) }
    Column {
        Row(Modifier.padding(12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { saver.launch("csr8510_$fileTs.btsnoop") }) { Text(stringResource(R.string.export_btsnoop)) }
            OutlinedButton(onClick = vm::togglePause) { Text(stringResource(if (paused) R.string.resume else R.string.pause)) }
            TextButton(onClick = vm::clearLog) { Text(stringResource(R.string.clear)) }
        }
        PacketList(recs, paused)
    }
}

// ======================= Classic =======================
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ClassicScreen(vm: AppViewModel) = NeedDongle(vm) {
    val list by vm.classicDevices.collectAsStateWithLifecycle()
    val conns by vm.classic.conns.collectAsStateWithLifecycle()
    val running by vm.inquiring.collectAsStateWithLifecycle()
    var sel by remember { mutableStateOf<String?>(null) }
    var manual by remember { mutableStateOf(false) }
    Column {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = vm::toggleInquiry) { Text(stringResource(if (running) R.string.scan_stop else R.string.inquiry_start)) }
                Spacer(Modifier.width(8.dp)); OutlinedButton(onClick = { manual = true }) { Text(stringResource(R.string.by_address)) }
                Spacer(Modifier.weight(1f)); TextButton(onClick = vm::clearClassic) { Text(stringResource(R.string.clear)) }
            }
            Text(stringResource(if (running) R.string.inquiry_running else R.string.classic_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (running) LinearProgressIndicator(Modifier.fillMaxWidth())
        val addrs = (list.map { it.address } + conns.keys).distinct()
        LazyColumn {
            items(addrs, key = { it }) { a ->
                val d = list.firstOrNull { it.address == a }; val c = conns[a]
                ListItem(modifier = Modifier.clickable { sel = a },
                    headlineContent = { Text(d?.name ?: stringResource(R.string.unnamed)) },
                    supportingContent = { Text(a + (d?.let { " · " + Assigned.cod(it.cod) } ?: ""), fontFamily = FontFamily.Monospace, fontSize = 12.sp) },
                    trailingContent = {
                        Column(horizontalAlignment = Alignment.End) {
                            d?.rssi?.let { Text("$it dBm", color = Palette.rssi(it)) }
                            if (c?.bonded == true) Badge(stringResource(R.string.paired), Palette.rx)
                            if (c?.state == ClState.CONNECTED) Badge(stringResource(R.string.gatt_connected), Palette.tx)
                        }
                    })
                HorizontalDivider()
            }
        }
    }
    if (manual) {
        var t by remember { mutableStateOf("") }
        AlertDialog(onDismissRequest = { manual = false }, title = { Text(stringResource(R.string.by_address)) },
            text = { OutlinedTextField(t, { t = it.uppercase() }, singleLine = true, placeholder = { Text("AA:BB:CC:DD:EE:FF") }) },
            confirmButton = { TextButton(onClick = { if (Regex("([0-9A-F]{2}:){5}[0-9A-F]{2}").matches(t)) { vm.classic.ensure(t); sel = t; manual = false } }) { Text("OK") } },
            dismissButton = { TextButton(onClick = { manual = false }) { Text(stringResource(R.string.close)) } })
    }
    sel?.let { a ->
        ModalBottomSheet(onDismissRequest = { sel = null }) { ClassicDetail(vm, a, list.firstOrNull { it.address == a }, conns[a] ?: ClassicConn(a)) }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ClassicDetail(vm: AppViewModel, a: String, d: ClassicDevice?, c: ClassicConn) {
    val cm = vm.classic
    Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp).padding(bottom = 32.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(d?.name ?: stringResource(R.string.unnamed), style = MaterialTheme.typography.headlineSmall)
        Text(a, fontFamily = FontFamily.Monospace)
        SectionCard(stringResource(R.string.status)) {
            KeyValue(stringResource(R.string.connection), when (c.state) { ClState.CONNECTED -> stringResource(R.string.gatt_connected) + " · handle 0x%03X".format(c.handle)
                ClState.CONNECTING -> stringResource(R.string.gatt_connecting); else -> stringResource(R.string.state_disconnected) })
            KeyValue(stringResource(R.string.pairing), (if (c.bonded) stringResource(R.string.paired) + (c.keyType?.let { " · key type $it" } ?: "") else stringResource(R.string.not_paired)) +
                (c.pairing?.let { "\n$it" } ?: ""))
            KeyValue(stringResource(R.string.security), listOfNotNull(if (c.authenticated) "Authenticated" else null, if (c.encrypted) "Encrypted 🔒" else "Not encrypted").joinToString(" · "))
            c.version?.let { KeyValue(stringResource(R.string.remote_version), it) }
            c.error?.let { Text(it, color = Palette.warn, style = MaterialTheme.typography.bodySmall) }
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (c.state != ClState.CONNECTED) Button(onClick = { cm.connect(a) }) { Text(stringResource(R.string.connect)) }
            else OutlinedButton(onClick = { cm.disconnect(a) }) { Text(stringResource(R.string.disconnect)) }
            FilledTonalButton(onClick = { cm.pair(a) }) { Text(stringResource(R.string.pair)) }
            FilledTonalButton(onClick = { cm.encrypt(a) }, enabled = c.state == ClState.CONNECTED) { Text(stringResource(R.string.encrypt)) }
            FilledTonalButton(onClick = { cm.sdp(a) }, enabled = !c.sdpBusy) { Text("SDP") }
            FilledTonalButton(onClick = { cm.remoteInfo(a) }) { Text(stringResource(R.string.remote_info)) }
            if (c.bonded) TextButton(onClick = { cm.forget(a) }) { Text(stringResource(R.string.forget)) }
        }
        if (c.sdpBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
        c.sdp?.let { recs ->
            SectionCard(stringResource(R.string.sdp_services, recs.size)) {
                recs.forEach { r ->
                    Column(Modifier.padding(vertical = 6.dp)) {
                        Text(r.name ?: r.classes.firstOrNull() ?: "Service", style = MaterialTheme.typography.bodyLarge)
                        r.classes.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            r.rfcomm?.let { Badge("RFCOMM ch $it", Palette.acl) }; r.psm?.let { Badge("PSM 0x%04X".format(it), Palette.evt) }
                        }
                        r.profiles.forEach { Text(it, style = MaterialTheme.typography.labelSmall) }
                    }
                    HorizontalDivider()
                }
            }
        }
        if (c.features.isNotEmpty()) SectionCard(stringResource(R.string.lmp_features)) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) { c.features.forEach { Badge(it, MaterialTheme.colorScheme.primary) } }
        }
    }
}

@Composable
fun PairingDialog(vm: AppViewModel) {
    val p by vm.classic.prompt.collectAsStateWithLifecycle()
    val pr = p ?: return
    var input by remember(pr) { mutableStateOf("") }
    AlertDialog(onDismissRequest = {},
        title = { Text(stringResource(R.string.pairing_request)) },
        text = { Column {
            Text(pr.address, fontFamily = FontFamily.Monospace)
            Spacer(Modifier.height(8.dp))
            when (pr.kind) {
                PromptKind.CONFIRM -> { Text(stringResource(R.string.confirm_code)); Text("%06d".format(pr.value ?: 0), style = MaterialTheme.typography.displaySmall) }
                PromptKind.PASSKEY_DISPLAY -> { Text(stringResource(R.string.enter_on_device)); Text("%06d".format(pr.value ?: 0), style = MaterialTheme.typography.displaySmall) }
                PromptKind.PASSKEY_ENTRY -> OutlinedTextField(input, { input = it.filter(Char::isDigit).take(6) }, label = { Text(stringResource(R.string.passkey)) }, singleLine = true)
                PromptKind.PIN -> OutlinedTextField(input, { input = it.take(16) }, label = { Text("PIN (e.g. 0000)") }, singleLine = true)
            } } },
        confirmButton = { TextButton(onClick = { vm.classic.answer(true, input) }) { Text(stringResource(if (pr.kind == PromptKind.PASSKEY_DISPLAY) R.string.close else R.string.pair)) } },
        dismissButton = { if (pr.kind != PromptKind.PASSKEY_DISPLAY) TextButton(onClick = { vm.classic.answer(false) }) { Text(stringResource(R.string.cancel)) } })
}

// ======================= GATT =======================
private fun parseInput(t: String, hex: Boolean): ByteArray? =
    if (!hex) t.toByteArray() else t.replace(" ", "").replace("0x", "").let { s -> if (s.length % 2 != 0 || !s.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) null else s.chunked(2).map { it.toInt(16).toByte() }.toByteArray() }

@Composable
private fun WriteDialog(title: String, allowCmd: Boolean, allowReq: Boolean, onWrite: (ByteArray, Boolean) -> Unit, onDismiss: () -> Unit) {
    var t by remember { mutableStateOf("") }; var hex by remember { mutableStateOf(true) }
    var withRsp by remember { mutableStateOf(allowReq) }
    val bytes = parseInput(t, hex)
    AlertDialog(onDismissRequest = onDismiss, title = { Text(title) }, text = { Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            FilterChip(hex, { hex = true }, { Text("HEX") }); Spacer(Modifier.width(6.dp)); FilterChip(!hex, { hex = false }, { Text("UTF-8") })
        }
        OutlinedTextField(t, { t = it }, Modifier.fillMaxWidth(), placeholder = { Text(if (hex) "01 00 FF" else "hello") }, isError = bytes == null,
            supportingText = { Text(bytes?.let { "${it.size} B: ${it.hex()}" } ?: "Invalid hex") })
        if (allowCmd && allowReq) Row(verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.with_response), Modifier.weight(1f)); Switch(withRsp, { withRsp = it }) }
        else Text(if (allowReq) "Write Request" else "Write Command", style = MaterialTheme.typography.labelMedium)
    } }, confirmButton = { TextButton(enabled = bytes != null, onClick = { onWrite(bytes!!, withRsp); onDismiss() }) { Text(stringResource(R.string.write)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } })
}

@Composable
fun GattScreen(vm: AppViewModel) = NeedDongle(vm) {
    val g by vm.gatt.collectAsStateWithLifecycle()
    var writeTarget by remember { mutableStateOf<Triple<Int, Boolean, Boolean>?>(null) } // handle, allowCmd, allowReq
    var capture by remember { mutableStateOf(false) }
    LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            SectionCard {
                Text(g.name ?: g.address ?: "GATT", style = MaterialTheme.typography.titleMedium)
                g.address?.let { Text(it, fontFamily = FontFamily.Monospace, fontSize = 12.sp) }
                Text(when (g.phase) {
                    GattPhase.IDLE -> g.message ?: stringResource(R.string.gatt_idle)
                    GattPhase.CONNECTING -> stringResource(R.string.gatt_connecting)
                    GattPhase.DISCOVERING -> stringResource(R.string.gatt_discovering)
                    GattPhase.CONNECTED -> stringResource(R.string.gatt_connected) + " · " + stringResource(R.string.services, g.services.size) + " · MTU ${g.mtu}"
                }, style = MaterialTheme.typography.bodySmall)
                if (g.phase == GattPhase.CONNECTING || g.phase == GattPhase.DISCOVERING) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                if (g.phase != GattPhase.IDLE || g.address != null) Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (g.phase != GattPhase.IDLE) OutlinedButton(onClick = vm::disconnectGatt) { Text(stringResource(R.string.disconnect)) }
                    if (g.phase == GattPhase.CONNECTED) FilledTonalButton(onClick = { vm.exchangeMtu() }) { Text("MTU 247") }
                    FilledTonalButton(onClick = { capture = true }, enabled = g.handle >= 0) { Text(stringResource(R.string.capture)) }
                }
            }
        }
        items(g.services, key = { it.start }) { s ->
            SectionCard {
                Text(Assigned.uuidName(s.uuid) ?: "Custom Service", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
                Text("${s.uuid} · 0x%04X–0x%04X".format(s.start, s.end), fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                s.chars.forEach { c ->
                    HorizontalDivider(Modifier.padding(vertical = 8.dp))
                    Text(Assigned.uuidName(c.uuid) ?: "Characteristic", style = MaterialTheme.typography.bodyLarge)
                    Text(c.uuid, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Badge("0x%04X".format(c.valueHandle), MaterialTheme.colorScheme.outline); Spacer(Modifier.width(4.dp)); Badge(c.propsText, Palette.acl)
                        if (c.notifyCount > 0) { Spacer(Modifier.width(4.dp)); Badge("● ${c.notifyCount} · ${fmtTime(c.lastUpdate)}", Palette.evt) }
                    }
                    Row {
                        if (c.props and 0x02 != 0) TextButton(onClick = { vm.readChar(c) }) { Text(stringResource(R.string.read)) }
                        if (c.props and 0x0C != 0) TextButton(onClick = { writeTarget = Triple(c.valueHandle, c.props and 0x04 != 0, c.props and 0x08 != 0) }) { Text(stringResource(R.string.write)) }
                        if (c.props and 0x30 != 0) TextButton(onClick = { vm.subscribe(c) }) {
                            val on = c.descs.firstOrNull { Assigned.short16(it.uuid) == 0x2902 }?.value?.let { it.isNotEmpty() && it[0].toInt() != 0 } == true
                            Text(stringResource(if (on) R.string.unsubscribe else R.string.subscribe)) }
                    }
                    c.value?.let { v ->
                        val txt = v.toString(Charsets.UTF_8)
                        val printable = v.isNotEmpty() && txt.all { it.code in 32..126 || it.code > 0x2E7F }
                        val nice = when { Assigned.short16(c.uuid) == 0x2A19 && v.isNotEmpty() -> "${v.u8(0)} %"; printable -> "\"$txt\""; else -> null }
                        nice?.let { Text(it, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium) }
                        HexBlock(v)
                    }
                    c.error?.let { Text(it, color = Palette.warn, style = MaterialTheme.typography.bodySmall) }
                    c.descs.forEach { d ->
                        Row(Modifier.padding(start = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text("↳ " + (Assigned.uuidName(d.uuid) ?: d.uuid) + " · 0x%04X".format(d.handle), style = MaterialTheme.typography.bodySmall)
                                d.value?.let { Text(it.hex(), fontFamily = FontFamily.Monospace, fontSize = 11.sp) }
                            }
                            TextButton(onClick = { vm.readDesc(d.handle) }) { Text(stringResource(R.string.read)) }
                            TextButton(onClick = { writeTarget = Triple(d.handle, false, true) }) { Text(stringResource(R.string.write)) }
                        }
                    }
                }
            }
        }
    }
    writeTarget?.let { (h, cmd, req) -> WriteDialog("Write 0x%04X".format(h), cmd, req, { v, rsp -> vm.writeAttr(h, v, rsp) }) { writeTarget = null } }
    if (capture) CaptureDialog(vm) { capture = false }
}

@Composable
private fun CaptureDialog(vm: AppViewModel, onClose: () -> Unit) {
    var recs by remember { mutableStateOf(vm.connectionPackets()) }
    val logVer by vm.log.collectAsStateWithLifecycle()
    LaunchedEffect(logVer) { recs = vm.connectionPackets() }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { u -> u?.let { vm.exportRecords(it, recs) } }
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column {
                Row(Modifier.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = onClose) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) }
                    Text(stringResource(R.string.capture), style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                    TextButton(onClick = { saver.launch("gatt_conn_$fileTs.btsnoop") }) { Text(stringResource(R.string.export_btsnoop)) }
                }
                PacketList(recs, false)
            }
        }
    }
}

// ======================= Phone built-in log (root, read-only) =======================
@Composable
fun PhoneLogScreen(vm: AppViewModel) {
    val viewer by vm.sysViewer.collectAsStateWithLifecycle()
    if (viewer != null) { PhoneLogViewer(vm, viewer!!); return }
    val probe by vm.sysProbe.collectAsStateWithLifecycle()
    val probing by vm.sysProbing.collectAsStateWithLifecycle()
    LazyColumn(contentPadding = PaddingValues(vertical = 8.dp)) {
        item {
            Column(Modifier.padding(horizontal = 12.dp)) {
                SectionCard(stringResource(R.string.phone_title)) {
                    Text(stringResource(R.string.phone_desc), style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    Button(onClick = vm::probeSystem, enabled = !probing) { Text(stringResource(R.string.check_root)) }
                    if (probing) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                    val p = probe
                    if (p != null && !p.root) Text(stringResource(R.string.needs_root), color = Palette.warn)
                    if (p != null && p.root) {
                        Text(stringResource(R.string.snoop_mode, p.mode), style = MaterialTheme.typography.labelMedium)
                        if (p.files.isEmpty()) { Text(stringResource(R.string.no_log_files), color = Palette.warn); Text(stringResource(R.string.enable_guide), style = MaterialTheme.typography.bodySmall) }
                        Text(stringResource(R.string.toggle_hint), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
        val p = probe
        if (p != null && p.root) {
            val newest = p.files.maxByOrNull { it.mtime }
            p.files.groupBy { it.path.substringBeforeLast('/') }.forEach { (dir, files) ->
                item(key = "dir:$dir") {
                    Text(dir + "/", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary, fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp))
                }
                items(files.sortedByDescending { it.mtime }, key = { it.path }) { f ->
                    ListItem(modifier = Modifier.clickable { vm.openSysFile(f, follow = false) },
                        headlineContent = { Text(f.path.substringAfterLast('/')) },
                        supportingContent = { Text("%.1f MB · %s".format(f.size / 1048576.0, SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(f.mtime)))) },
                        trailingContent = { if (f == newest) TextButton(onClick = { vm.openSysFile(f, follow = true) }) { Text(stringResource(R.string.live_follow)) } })
                }
            }
            item(key = "diag") {
                var open by remember { mutableStateOf(false) }
                Column(Modifier.padding(horizontal = 16.dp)) {
                    TextButton(onClick = { open = !open }) { Text(stringResource(R.string.diagnostics) + if (open) " ▲" else " ▼") }
                    if (open) Text(p.diag.joinToString("\n"), fontFamily = FontFamily.Monospace, fontSize = 10.sp, lineHeight = 13.sp)
                }
            }
        }
    }
}

@Composable
private fun PhoneLogViewer(vm: AppViewModel, f: SystemSnoop.SnoopFile) {
    val recs by vm.sysLog.collectAsStateWithLifecycle()
    val progress by vm.sysProgress.collectAsStateWithLifecycle()
    val running by vm.sysTailing.collectAsStateWithLifecycle()
    val follow by vm.sysFollow.collectAsStateWithLifecycle()
    val paused by vm.sysPaused.collectAsStateWithLifecycle()
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { it?.let(vm::exportSys) }
    BackHandler { vm.closeSysViewer() }
    Column {
        Row(Modifier.padding(horizontal = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = vm::closeSysViewer) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) }
            Column(Modifier.weight(1f)) {
                Text(f.path.substringAfterLast('/'), style = MaterialTheme.typography.titleMedium, maxLines = 1)
                Text(when { follow && running -> stringResource(R.string.following); running -> stringResource(R.string.loading_pct, (progress * 100).toInt()); else -> stringResource(R.string.loaded) },
                    style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(stringResource(R.string.live_follow), style = MaterialTheme.typography.labelMedium)
            Switch(follow, { vm.openSysFile(f, follow = it) }, Modifier.padding(horizontal = 8.dp))
        }
        if (running && !follow) LinearProgressIndicator({ progress }, Modifier.fillMaxWidth()) else if (running) LinearProgressIndicator(Modifier.fillMaxWidth())
        Row(Modifier.padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = vm::toggleSysPause) { Text(stringResource(if (paused) R.string.resume else R.string.pause)) }
            TextButton(onClick = { saver.launch("phone_btsnoop_$fileTs.log") }) { Text(stringResource(R.string.export_copy)) }
        }
        PacketList(recs, paused, autoScroll = follow)
    }
}
