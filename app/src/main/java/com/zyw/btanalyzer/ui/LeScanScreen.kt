package com.zyw.btanalyzer.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.zyw.btanalyzer.*
import com.zyw.btanalyzer.R
import kotlinx.coroutines.delay
import kotlin.math.pow

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun LeScanScreen(vm: AppViewModel, onOpenGatt: () -> Unit) = NeedDongle(vm) {
    val all by vm.leDevices.collectAsStateWithLifecycle()
    val scanning by vm.scanning.collectAsStateWithLifecycle()
    val active by vm.activeScan.collectAsStateWithLifecycle()
    var filter by rememberSaveable { mutableStateOf("") }
    var sort by rememberSaveable { mutableStateOf(SortMode.RSSI) }
    var minRssi by rememberSaveable { mutableFloatStateOf(-100f) }
    var selected by remember { mutableStateOf<String?>(null) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) { while (true) { delay(1000); now = System.currentTimeMillis() } }

    val list = remember(all, filter, sort, minRssi) {
        val q = filter.trim().lowercase()
        all.filter { it.rssi >= minRssi && (q.isEmpty() || it.address.lowercase().contains(q) || (it.name ?: "").lowercase().contains(q) || it.info.tags.any { t -> t.lowercase().contains(q) }) }
            .let { l -> when (sort) { SortMode.RSSI -> l.sortedByDescending { it.rssi }; SortMode.NAME -> l.sortedWith(compareBy({ it.name == null }, { it.name?.lowercase() })); SortMode.RECENT -> l.sortedByDescending { it.lastSeen } } }
    }

    Column {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = vm::toggleScan) { Text(stringResource(if (scanning) R.string.scan_stop else R.string.scan_start)) }
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.active), style = MaterialTheme.typography.bodyLarge)
                Spacer(Modifier.width(8.dp))
                Switch(active, { vm.activeScan.value = it }, enabled = !scanning)
                Spacer(Modifier.weight(1f))
                TextButton(onClick = vm::clearLe) { Text(stringResource(R.string.clear)) }
            }
            OutlinedTextField(filter, { filter = it }, Modifier.fillMaxWidth(), singleLine = true, placeholder = { Text(stringResource(R.string.filter_hint)) })
            Row(verticalAlignment = Alignment.CenterVertically) {
                listOf(SortMode.RSSI to R.string.sort_rssi, SortMode.NAME to R.string.sort_name, SortMode.RECENT to R.string.sort_recent).forEach { (m, r) ->
                    FilterChip(sort == m, { sort = m }, { Text(stringResource(r)) }); Spacer(Modifier.width(6.dp))
                }
                Spacer(Modifier.weight(1f))
                Text(stringResource(R.string.devices_count, list.size), style = MaterialTheme.typography.labelMedium)
            }
            Text(stringResource(R.string.min_rssi, minRssi.toInt()), style = MaterialTheme.typography.labelSmall)
            Slider(minRssi, { minRssi = it }, valueRange = -100f..-30f, modifier = Modifier.height(28.dp))
        }
        if (scanning) LinearProgressIndicator(Modifier.fillMaxWidth())
        LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(list, key = { it.address }) { d -> DeviceCard(d, now) { selected = d.address } }
        }
    }

    val sel = selected?.let { a -> all.firstOrNull { it.address == a } }
    if (sel != null) {
        ModalBottomSheet(onDismissRequest = { selected = null }, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
            DeviceDetail(sel, onConnect = { vm.connectGatt(sel); selected = null; onOpenGatt() })
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DeviceCard(d: LeDevice, now: Long, onClick: () -> Unit) {
    OutlinedCard(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(d.name ?: stringResource(R.string.unnamed), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium, maxLines = 1,
                    color = if (d.name == null) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface)
                Text("${d.address} · ${d.addrTypeName}", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(4.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    d.info.tags.filter { it != "Unknown" }.take(4).forEach { Badge(it, MaterialTheme.colorScheme.primary) }
                    Badge(stringResource(if (d.connectable) R.string.connectable else R.string.non_connectable), if (d.connectable) Palette.acl else MaterialTheme.colorScheme.outline)
                }
                Spacer(Modifier.height(2.dp))
                Text(stringResource(R.string.seen_count, d.count, stringResource(R.string.ago_s, ((now - d.lastSeen) / 1000).coerceAtLeast(0).toInt())),
                    style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("${d.rssi}", style = MaterialTheme.typography.headlineSmall, color = Palette.rssi(d.rssi), fontWeight = FontWeight.Bold)
                Text("dBm", style = MaterialTheme.typography.labelSmall)
                RssiChart(d.history, Modifier.width(80.dp).height(28.dp), compact = true)
            }
        }
    }
}

@Composable
fun RssiChart(h: List<Pair<Long, Int>>, modifier: Modifier, compact: Boolean = false) {
    val line = MaterialTheme.colorScheme.primary; val grid = MaterialTheme.colorScheme.outlineVariant
    Canvas(modifier) {
        if (h.size < 2) return@Canvas
        val lo = -100f; val hi = -20f
        if (!compact) for (v in listOf(-90, -70, -50, -30)) { val y = size.height * (1 - (v - lo) / (hi - lo)); drawLine(grid, Offset(0f, y), Offset(size.width, y), 1f) }
        val t0 = h.first().first; val span = (h.last().first - t0).coerceAtLeast(1)
        val p = Path()
        h.forEachIndexed { i, (t, r) ->
            val x = size.width * (t - t0) / span; val y = size.height * (1 - (r.coerceIn(-100, -20) - lo) / (hi - lo))
            if (i == 0) p.moveTo(x, y) else p.lineTo(x, y)
        }
        drawPath(p, line, style = Stroke(if (compact) 2f else 4f))
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DeviceDetail(d: LeDevice, onConnect: () -> Unit) {
    var raw by remember { mutableStateOf(false) }
    Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp).padding(bottom = 32.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(d.name ?: stringResource(R.string.unnamed), style = MaterialTheme.typography.headlineSmall)
                Text(d.address, fontFamily = FontFamily.Monospace)
            }
            Text("${d.rssi} dBm", style = MaterialTheme.typography.titleLarge, color = Palette.rssi(d.rssi))
        }
        if (d.connectable) Button(onClick = onConnect, Modifier.fillMaxWidth()) { Text(stringResource(R.string.gatt_connect)) }
        SectionCard(stringResource(R.string.rssi_chart)) {
            RssiChart(d.history, Modifier.fillMaxWidth().height(140.dp))
            val rs = d.history.map { it.second }
            if (rs.isNotEmpty()) Text("min ${rs.min()} · avg ${rs.average().toInt()} · max ${rs.max()} dBm  (n=${rs.size})", style = MaterialTheme.typography.labelSmall)
        }
        SectionCard {
            KeyValue(stringResource(R.string.address), d.address, true)
            KeyValue(stringResource(R.string.addr_type), d.addrTypeName)
            d.info.txPower?.let { tx ->
                KeyValue(stringResource(R.string.tx_power), "$tx dBm")
                val dist = 10.0.pow(((tx - 41) - d.rssi) / 20.0)
                KeyValue("", stringResource(R.string.est_distance, "%.1f".format(dist)))
            }
        }
        SectionCard(stringResource(R.string.ad_structures)) {
            d.info.items.forEach { it ->
                Column(Modifier.padding(vertical = 5.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Badge("0x%02X".format(it.type and 0xff), MaterialTheme.colorScheme.outline); Spacer(Modifier.width(6.dp))
                        Text(it.typeName, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Medium)
                    }
                    Text(it.decoded, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = 4.dp, top = 2.dp))
                }
                HorizontalDivider()
            }
            TextButton(onClick = { raw = !raw }) { Text(stringResource(if (raw) R.string.hide_raw else R.string.show_raw)) }
            if (raw) {
                Text(stringResource(R.string.adv_data), style = MaterialTheme.typography.labelMedium); HexBlock(d.adv)
                d.scanRsp?.let { Spacer(Modifier.height(6.dp)); Text(stringResource(R.string.scan_rsp), style = MaterialTheme.typography.labelMedium); HexBlock(it) }
            }
        }
    }
}
