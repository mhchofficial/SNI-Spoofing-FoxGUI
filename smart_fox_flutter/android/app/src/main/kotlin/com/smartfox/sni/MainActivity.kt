package com.smartfox.sni

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.EventChannel
import android.content.Intent
import android.net.VpnService
import android.app.Activity
import android.os.Bundle
import android.util.Log

class MainActivity : FlutterActivity() {
    companion object {
        private const val TAG = "SmartFoxMain"
        private const val METHOD_CHANNEL = "com.smartfox.sni/vpn"
        private const val EVENT_CHANNEL = "com.smartfox.sni/vpn_events"
        private const val VPN_REQUEST_CODE = 100
        
        var instance: MainActivity? = null
    }
    
    private var methodChannel: MethodChannel? = null
    private var eventChannel: EventChannel? = null
    private var pendingResult: MethodChannel.Result? = null
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        instance = this
    }
    
    override fun onDestroy() {
        super.onDestroy()
        instance = null
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        // Method Channel for VPN control
        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
        methodChannel?.setMethodCallHandler { call, result ->
            when (call.method) {
                "initialize" -> {
                    result.success(true)
                }
                "startVpn" -> {
                    val config = call.argument<Map<String, Any>>("config")
                    if (config != null) {
                        startVpnService(config, result)
                    } else {
                        result.error("INVALID_CONFIG", "Configuration is required", null)
                    }
                }
                "stopVpn" -> {
                    stopVpnService()
                    result.success(true)
                }
                "isRunning" -> {
                    result.success(SmartFoxVpnService.isRunning)
                }
                "getStats" -> {
                    val stats = SmartFoxVpnService.getStats()
                    result.success(stats)
                }
                "testConnection" -> {
                    val host = call.argument<String>("host") ?: ""
                    val port = call.argument<Int>("port") ?: 443
                    testConnection(host, port, result)
                }
                "checkPermissions" -> {
                    val intent = VpnService.prepare(this)
                    result.success(intent == null)
                }
                "requestPermissions" -> {
                    requestVpnPermission(result)
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
        
        // Event Channel for real-time updates
        eventChannel = EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL)
        eventChannel?.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                SmartFoxVpnService.eventSink = events
            }
            
            override fun onCancel(arguments: Any?) {
                SmartFoxVpnService.eventSink = null
            }
        })
    }
    
    private fun startVpnService(config: Map<String, Any>, result: MethodChannel.Result) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            pendingResult = result
            SmartFoxVpnService.pendingConfig = config
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            // Permission already granted
            doStartVpnService(config)
            result.success(true)
        }
    }
    
    private fun doStartVpnService(config: Map<String, Any>) {
        val intent = Intent(this, SmartFoxVpnService::class.java).apply {
            action = SmartFoxVpnService.ACTION_START
            putExtra("config", HashMap(config))
        }
        startForegroundService(intent)
    }
    
    private fun stopVpnService() {
        val intent = Intent(this, SmartFoxVpnService::class.java).apply {
            action = SmartFoxVpnService.ACTION_STOP
        }
        startService(intent)
    }
    
    private fun requestVpnPermission(result: MethodChannel.Result) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            pendingResult = result
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            result.success(true)
        }
    }
    
    private fun testConnection(host: String, port: Int, result: MethodChannel.Result) {
        Thread {
            try {
                val socket = java.net.Socket()
                socket.connect(java.net.InetSocketAddress(host, port), 5000)
                socket.close()
                runOnUiThread { result.success(true) }
            } catch (e: Exception) {
                Log.e(TAG, "Connection test failed: ${e.message}")
                runOnUiThread { result.success(false) }
            }
        }.start()
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                val config = SmartFoxVpnService.pendingConfig
                if (config != null) {
                    doStartVpnService(config)
                    SmartFoxVpnService.pendingConfig = null
                }
                pendingResult?.success(true)
            } else {
                pendingResult?.success(false)
            }
            pendingResult = null
        }
    }
}
