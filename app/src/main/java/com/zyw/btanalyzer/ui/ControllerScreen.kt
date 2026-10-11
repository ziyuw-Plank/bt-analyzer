package com.zyw.btanalyzer.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.zyw.btanalyzer.*
import com.zyw.btanalyzer.R

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ControllerScreen(vm: AppViewModel, onConnect: () -> Unit) {
    val link by vm.link.collectAsStateWithLifecycle()
    val info by vm.info.collectAsStateWithLifecycle()
    val label by vm.deviceLabel.collectAsStateWithLifecycle()
    Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionCard {
            Text(label ?: "CSR8510 A10 · 0A12:0001", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.connect_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(12.dp))
            if (link == LinkState.READY) OutlinedButton(onClick = vm::disconnectUsb) { Text(stringResource(R.string.disconnect)) }
            else Button(onClick = onConnect, enabled = link != LinkState.CONNECTING) {
                if (link == LinkState.CONNECTING) { CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp); Spacer(Modifier.width(8.dp)) }
                Text(stringResource(R.string.connect_dongle))
            }
        }
        if (info.rows.isNotEmpty()) {
            SectionCard {
                if (info.cloneWarning != null) Badge("⚠ " + stringResource(R.string.clone_warning), Palette.warn)
                else Badge("✓ " + stringResource(R.string.genuine_hint), Palette.rx)
                info.cloneWarning?.let { Spacer(Modifier.height(6.dp)); Text(it, color = Palette.warn, style = MaterialTheme.typography.bodySmall) }
            }
            SectionCard(stringResource(R.string.controller_info)) { info.rows.forEach { KeyValue(it.label, it.value, mono = it.value.contains(":") || it.value.length > 20) } }
            SectionCard(stringResource(R.string.lmp_features)) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    info.lmpFeatures.forEach { Badge(it, MaterialTheme.colorScheme.primary) }
                }
            }
            if (info.leFeatures.isNotEmpty() || info.leSupported) SectionCard(stringResource(R.string.le_features)) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    (if (info.leFeatures.isEmpty()) listOf("LE 4.0 basic") else info.leFeatures).forEach { Badge(it, Palette.acl) }
                }
            }
        }
    }
}
