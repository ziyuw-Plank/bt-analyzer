package com.zyw.btanalyzer

import android.app.PendingIntent
import android.content.*
import android.content.res.Configuration
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import com.zyw.btanalyzer.ui.AppRoot
import java.util.Locale

class MainActivity : ComponentActivity() {
    private val vm: AppViewModel by viewModels()
    private val usb by lazy { getSystemService(UsbManager::class.java) }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            val dev = i.usbDevice() ?: return
            when (i.action) {
                ACTION_PERMISSION -> if (i.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false) || usb.hasPermission(dev)) vm.connect(dev)
                    else Toast.makeText(c, R.string.permission_denied, Toast.LENGTH_SHORT).show()
                UsbManager.ACTION_USB_DEVICE_DETACHED -> vm.onDetached(dev)
            }
        }
    }

    override fun attachBaseContext(base: Context) {
        val lang = base.getSharedPreferences("prefs", MODE_PRIVATE).getString("lang", "") ?: ""
        if (lang.isEmpty()) { super.attachBaseContext(base); return }
        val loc = if (lang == "zh") Locale.SIMPLIFIED_CHINESE else Locale.ENGLISH
        Locale.setDefault(loc)
        val cfg = Configuration(base.resources.configuration); cfg.setLocale(loc)
        super.attachBaseContext(base.createConfigurationContext(cfg))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        ContextCompat.registerReceiver(this, receiver, IntentFilter().apply {
            addAction(ACTION_PERMISSION); addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }, ContextCompat.RECEIVER_NOT_EXPORTED)
        handleIntent(intent)
        val lang = getSharedPreferences("prefs", MODE_PRIVATE).getString("lang", "") ?: ""
        setContent { AppRoot(vm, onConnect = ::requestConnect, lang = lang, onLang = ::setLang) }
    }

    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); handleIntent(intent) }

    private fun handleIntent(i: Intent?) {
        if (i?.action == UsbManager.ACTION_USB_DEVICE_ATTACHED) i.usbDevice()?.let { if (usb.hasPermission(it)) vm.connect(it) else askPermission(it) }
    }

    private fun requestConnect() {
        val d = vm.findDongles().firstOrNull()
        if (d == null) { Toast.makeText(this, R.string.no_dongle_found, Toast.LENGTH_LONG).show(); return }
        if (usb.hasPermission(d)) vm.connect(d) else askPermission(d)
    }

    private fun askPermission(d: UsbDevice) {
        val flags = if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
        val pi = PendingIntent.getBroadcast(this, 0, Intent(ACTION_PERMISSION).setPackage(packageName), flags)
        usb.requestPermission(d, pi)
    }

    private fun setLang(l: String) {
        getSharedPreferences("prefs", MODE_PRIVATE).edit().putString("lang", l).apply()
        recreate()
    }

    override fun onDestroy() { unregisterReceiver(receiver); super.onDestroy() }

    private fun Intent.usbDevice(): UsbDevice? =
        if (Build.VERSION.SDK_INT >= 33) getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
        else @Suppress("DEPRECATION") getParcelableExtra(UsbManager.EXTRA_DEVICE)

    companion object { const val ACTION_PERMISSION = "com.zyw.btanalyzer.USB_PERMISSION" }
}
