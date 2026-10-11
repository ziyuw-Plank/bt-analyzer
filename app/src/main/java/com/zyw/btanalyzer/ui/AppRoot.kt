package com.zyw.btanalyzer.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import kotlinx.coroutines.launch
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.zyw.btanalyzer.*
import com.zyw.btanalyzer.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRoot(vm: AppViewModel, onConnect: () -> Unit, lang: String, onLang: (String) -> Unit) = AppTheme {
    val link by vm.link.collectAsStateWithLifecycle()
    val devLabel by vm.deviceLabel.collectAsStateWithLifecycle()
    var page by rememberSaveable { mutableIntStateOf(0) }
    val snack = remember { SnackbarHostState() }
    LaunchedEffect(Unit) { vm.messages.collect { snack.showSnackbar(it, withDismissAction = true) } }
    var langMenu by remember { mutableStateOf(false) }
    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val pages = listOf(
        R.string.tab_controller to Icons.Default.Build, R.string.tab_le to Icons.Default.Search,
        R.string.tab_classic to Icons.Default.Refresh, R.string.tab_gatt to Icons.Default.Share,
        R.string.tab_log to Icons.AutoMirrored.Filled.List, R.string.tab_phone to Icons.Default.Phone)
    val (statusTxt, statusCol) = when (link) {
        LinkState.READY -> R.string.state_ready to Palette.rx
        LinkState.CONNECTING -> R.string.state_connecting to Palette.cmd
        LinkState.ERROR -> R.string.state_error to Palette.warn
        else -> R.string.state_disconnected to MaterialTheme.colorScheme.outline
    }

    PairingDialog(vm)
    BackHandler(enabled = drawer.isOpen) { scope.launch { drawer.close() } }

    ModalNavigationDrawer(drawerState = drawer, drawerContent = {
        ModalDrawerSheet {
            Row(Modifier.padding(horizontal = 28.dp, vertical = 20.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(40.dp).clip(CircleShape)) {
                    Image(painterResource(R.drawable.ic_launcher_background), null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
                    Image(painterResource(R.drawable.ic_launcher_foreground), null, Modifier.fillMaxSize().scale(1.5f))
                }
                Spacer(Modifier.width(16.dp))
                Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge)
            }
            HorizontalDivider(Modifier.padding(horizontal = 28.dp))
            Spacer(Modifier.height(8.dp))
            pages.forEachIndexed { i, (label, icon) ->
                NavigationDrawerItem(
                    label = { Text(stringResource(label)) }, icon = { Icon(icon, null) }, selected = page == i,
                    onClick = { page = i; scope.launch { drawer.close() } },
                    modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding))
            }
            Spacer(Modifier.weight(1f))
            HorizontalDivider(Modifier.padding(horizontal = 28.dp))
            ListItem(
                headlineContent = { Text(stringResource(statusTxt)) },
                supportingContent = { Text(devLabel ?: "CSR8510 A10 · 0A12:0001") },
                leadingContent = { Box(Modifier.size(12.dp).clip(CircleShape).background(statusCol)) },
                colors = ListItemDefaults.colors(containerColor = androidx.compose.ui.graphics.Color.Transparent),
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp))
        }
    }) {
        Scaffold(
            snackbarHost = { SnackbarHost(snack) },
            topBar = {
                TopAppBar(
                    navigationIcon = { IconButton(onClick = { scope.launch { drawer.open() } }) { Icon(Icons.Default.Menu, contentDescription = "Menu") } },
                    title = { Text(stringResource(pages[page].first)) },
                    actions = {
                        Badge(stringResource(statusTxt), statusCol)
                        Box {
                            IconButton(onClick = { langMenu = true }) { Text(if (lang == "en") "EN" else if (lang == "zh") "中" else "A文") }
                            DropdownMenu(langMenu, { langMenu = false }) {
                                listOf("" to stringResource(R.string.lang_system), "zh" to "简体中文", "en" to "English").forEach { (k, n) ->
                                    DropdownMenuItem(text = { Text(n) }, onClick = { langMenu = false; if (k != lang) onLang(k) },
                                        leadingIcon = { if (k == lang) Icon(Icons.Default.Check, null) })
                                }
                            }
                        }
                    })
            }
        ) { pad ->
            Box(Modifier.padding(pad).fillMaxSize()) {
                when (page) {
                    0 -> ControllerScreen(vm, onConnect)
                    1 -> LeScanScreen(vm, onOpenGatt = { page = 3 })
                    2 -> ClassicScreen(vm)
                    3 -> GattScreen(vm)
                    4 -> LogScreen(vm)
                    5 -> PhoneLogScreen(vm)
                }
            }
        }
    }
}

@Composable
fun NeedDongle(vm: AppViewModel, content: @Composable () -> Unit) {
    val link by vm.link.collectAsStateWithLifecycle()
    if (link == LinkState.READY) content() else EmptyHint(stringResource(R.string.connect_hint))
}
