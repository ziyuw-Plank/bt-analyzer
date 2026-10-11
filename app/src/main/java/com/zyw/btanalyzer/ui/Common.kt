package com.zyw.btanalyzer.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.os.Build
import com.zyw.btanalyzer.hci.HciRecord
import com.zyw.btanalyzer.hci.PktType
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun AppTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme(); val ctx = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme(primary = Color(0xFF8AB4F8)) else -> lightColorScheme(primary = Color(0xFF1A73E8))
    }
    MaterialTheme(colorScheme = scheme, typography = systemTypography(), content = content)
}

/** Force the stock Roboto/Google Sans system font so OEM theme fonts (e.g. handwriting on MIUI/HyperOS) are not used. */
private val stockFamily: FontFamily by lazy {
    val candidates = listOf("/system/fonts/Roboto-Regular.ttf", "/system/fonts/RobotoStatic-Regular.ttf", "/system/fonts/GoogleSans-Regular.ttf")
    val tf = candidates.firstNotNullOfOrNull { p -> runCatching { java.io.File(p).takeIf { it.exists() }?.let { android.graphics.Typeface.createFromFile(it) } }.getOrNull() }
    if (tf != null) FontFamily(tf) else FontFamily.SansSerif
}

private fun systemTypography(): Typography {
    val t = Typography(); val f = stockFamily
    return Typography(
        displayLarge = t.displayLarge.copy(fontFamily = f), displayMedium = t.displayMedium.copy(fontFamily = f), displaySmall = t.displaySmall.copy(fontFamily = f),
        headlineLarge = t.headlineLarge.copy(fontFamily = f), headlineMedium = t.headlineMedium.copy(fontFamily = f), headlineSmall = t.headlineSmall.copy(fontFamily = f),
        titleLarge = t.titleLarge.copy(fontFamily = f), titleMedium = t.titleMedium.copy(fontFamily = f), titleSmall = t.titleSmall.copy(fontFamily = f),
        bodyLarge = t.bodyLarge.copy(fontFamily = f), bodyMedium = t.bodyMedium.copy(fontFamily = f), bodySmall = t.bodySmall.copy(fontFamily = f),
        labelLarge = t.labelLarge.copy(fontFamily = f), labelMedium = t.labelMedium.copy(fontFamily = f), labelSmall = t.labelSmall.copy(fontFamily = f),
    )
}

@Composable
fun Badge(text: String, color: Color, modifier: Modifier = Modifier) {
    Box(modifier.clip(RoundedCornerShape(8.dp)).background(color.copy(alpha = 0.12f)).padding(horizontal = 8.dp, vertical = 2.dp)) {
        Text(text, color = color, style = MaterialTheme.typography.labelSmall, maxLines = 1)
    }
}

object Palette {
    val tx = Color(0xFF1E88E5); val rx = Color(0xFF43A047)
    val cmd = Color(0xFFF57C00); val evt = Color(0xFF8E24AA); val acl = Color(0xFF00897B)
    val warn = Color(0xFFE53935)
    fun rssi(r: Int) = when { r >= -60 -> Color(0xFF43A047); r >= -75 -> Color(0xFF7CB342); r >= -85 -> Color(0xFFFFA000); else -> Color(0xFFE53935) }
    fun type(t: PktType) = when (t) { PktType.CMD -> cmd; PktType.EVT -> evt; PktType.ACL -> acl }
}

@Composable
fun SectionCard(title: String? = null, modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier.fillMaxWidth()) {
        if (title != null) Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(start = 16.dp, bottom = 8.dp, top = 4.dp))
        Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp)) {
            content()
        } }
    }
}

@Composable
fun KeyValue(k: String, v: String, mono: Boolean = false) {
    // Settings-style two-line row: label on top, value below
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        if (k.isNotEmpty()) Text(k, style = MaterialTheme.typography.bodyLarge)
        SelectionContainer { Text(v, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontFamily = if (mono) FontFamily.Monospace else null) }
    }
}

@Composable
fun HexBlock(bytes: ByteArray) {
    val lines = bytes.toList().chunked(16).mapIndexed { i, c ->
        "%04X  ".format(i * 16) + c.joinToString(" ") { "%02X".format(it.toInt() and 0xff) }
    }
    SelectionContainer {
        Text(lines.joinToString("\n"), fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 15.sp,
            modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(8.dp))
    }
}

private val timeFmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
fun fmtTime(ms: Long): String = synchronized(timeFmt) { timeFmt.format(Date(ms)) }

@Composable
fun EmptyHint(text: String) {
    Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
        Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
    }
}

/** Shared HCI packet row: colored badges + readable one-line summary. Tap opens detail sheet. */
@Composable
fun PacketRow(r: HciRecord, txLabel: String, rxLabel: String, onClick: () -> Unit) {
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        overlineContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(fmtTime(r.timeMs), fontFamily = FontFamily.Monospace)
                Spacer(Modifier.width(6.dp)); Badge(if (r.sent) "→ $txLabel" else "← $rxLabel", if (r.sent) Palette.tx else Palette.rx)
                Spacer(Modifier.width(4.dp)); Badge(com.zyw.btanalyzer.hci.HciController.category(r.type, r.data), Palette.type(r.type))
            }
        },
        headlineContent = {
            Text(r.summary, style = MaterialTheme.typography.bodyMedium, maxLines = 2,
                color = if (r.summary.contains("status=0x00") || !r.summary.contains("status=")) MaterialTheme.colorScheme.onSurface else Palette.warn)
        })
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PacketDetailSheet(r: HciRecord, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp).padding(bottom = 32.dp)) {
            Text(r.summary, style = MaterialTheme.typography.titleMedium)
            Text("${fmtTime(r.timeMs)} · ${if (r.sent) "Host → Controller" else "Controller → Host"} · ${r.data.size} B",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(12.dp))
            com.zyw.btanalyzer.hci.HciController.details(r.type, r.data).forEach { (k, v) -> KeyValue(k, v, mono = v.length > 2 && v[2] == ' ') }
            Spacer(Modifier.height(8.dp)); HexBlock(r.data)
        }
    }
}
