package com.smartfox.sni

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import io.flutter.plugin.common.EventChannel
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

class SmartFoxVpnService : VpnService() {
    companion object {
        private const val TAG = "SmartFoxVPN"
        const val ACTION_START = "com.smartfox.sni.START"
        const val ACTION_STOP = "com.smartfox.sni.STOP"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "SmartFoxVPN"
        
        var isRunning = false
            private set
        var eventSink: EventChannel.EventSink? = null
        var pendingConfig: Map<String, Any>? = null
        
        // Statistics
        private val bytesIn = AtomicLong(0)
        private val bytesOut = AtomicLong(0)
        private val packetsProcessed = AtomicLong(0)
        private var startTime: Long = 0
        
        fun getStats(): Map<String, Any> {
            return mapOf(
                "bytesIn" to bytesIn.get(),
                "bytesOut" to bytesOut.get(),
                "packetsProcessed" to packetsProcessed.get(),
                "activeConnections" to activeConnections.size,
                "uptime" to if (startTime > 0) (System.currentTimeMillis() - startTime) / 1000 else 0
            )
        }
        
        private val activeConnections = ConcurrentHashMap<String, ConnectionState>()
    }
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var workerThread: Thread? = null
    
    // Configuration
    private var config: VpnConfig? = null
    
    data class VpnConfig(
        val fakeSni: String,
        val realSni: String,
        val listenPort: Int,
        val remotePort: Int,
        val bufferSize: Int,
        val timeout: Int,
        val enableFakeTcpHandshake: Boolean,
        val tcpTtl: Int,
        val tcpMss: Int,
        val tcpWindowSize: Int,
        val tlsVersion: String,
        val splitMode: String,
        val injectionMethod: String,
        val dpiBypassLevel: Int,
        val enableFragmentation: Boolean,
        val fragmentSize: Int,
        val randomizeFragments: Boolean
    )
    
    data class ConnectionState(
        val remoteAddress: String,
        val remotePort: Int,
        var state: String,
        var bytesSent: Long = 0,
        var bytesReceived: Long = 0
    )

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                @Suppress("UNCHECKED_CAST")
                val configMap = intent.getSerializableExtra("config") as? HashMap<String, Any>
                if (configMap != null) {
                    config = parseConfig(configMap)
                    startVpn()
                }
            }
            ACTION_STOP -> {
                stopVpn()
            }
        }
        return START_STICKY
    }
    
    private fun parseConfig(map: Map<String, Any>): VpnConfig {
        return VpnConfig(
            fakeSni = map["fakeSni"] as? String ?: "www.google.com",
            realSni = map["realSni"] as? String ?: "",
            listenPort = (map["listenPort"] as? Number)?.toInt() ?: 443,
            remotePort = (map["remotePort"] as? Number)?.toInt() ?: 443,
            bufferSize = (map["bufferSize"] as? Number)?.toInt() ?: 65535,
            timeout = (map["timeout"] as? Number)?.toInt() ?: 30,
            enableFakeTcpHandshake = map["enableFakeTcpHandshake"] as? Boolean ?: false,
            tcpTtl = (map["tcpTtl"] as? Number)?.toInt() ?: 64,
            tcpMss = (map["tcpMss"] as? Number)?.toInt() ?: 1460,
            tcpWindowSize = (map["tcpWindowSize"] as? Number)?.toInt() ?: 65535,
            tlsVersion = map["tlsVersion"] as? String ?: "tls12",
            splitMode = map["splitMode"] as? String ?: "sni",
            injectionMethod = map["injectionMethod"] as? String ?: "standard",
            dpiBypassLevel = (map["dpiBypassLevel"] as? Number)?.toInt() ?: 1,
            enableFragmentation = map["enableFragmentation"] as? Boolean ?: false,
            fragmentSize = (map["fragmentSize"] as? Number)?.toInt() ?: 100,
            randomizeFragments = map["randomizeFragments"] as? Boolean ?: false
        )
    }

    private fun startVpn() {
        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return
        }
        
        try {
            // Build VPN interface
            val builder = Builder()
                .setSession("SmartFox SNI")
                .setMtu(1500)
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
            
            // Allow bypass for local apps if needed
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            
            vpnInterface = builder.establish()
            
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                sendEvent("error", "Failed to establish VPN interface")
                return
            }
            
            running.set(true)
            isRunning = true
            startTime = System.currentTimeMillis()
            
            // Start foreground notification
            startForeground(NOTIFICATION_ID, createNotification())
            
            // Start packet processing thread
            workerThread = thread(name = "SmartFoxVPN-Worker") {
                processPackets()
            }
            
            sendEvent("started", null)
            Log.i(TAG, "VPN started successfully")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN: ${e.message}", e)
            sendEvent("error", e.message)
            stopVpn()
        }
    }
    
    private fun stopVpn() {
        Log.i(TAG, "Stopping VPN...")
        running.set(false)
        isRunning = false
        
        workerThread?.interrupt()
        workerThread = null
        
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface: ${e.message}")
        }
        vpnInterface = null
        
        activeConnections.clear()
        bytesIn.set(0)
        bytesOut.set(0)
        packetsProcessed.set(0)
        startTime = 0
        
        stopForeground(STOP_FOREGROUND_REMOVE)
        sendEvent("stopped", null)
        stopSelf()
    }
    
    private fun processPackets() {
        val vpnFd = vpnInterface ?: return
        val inputStream = FileInputStream(vpnFd.fileDescriptor)
        val outputStream = FileOutputStream(vpnFd.fileDescriptor)
        
        val buffer = ByteBuffer.allocate(config?.bufferSize ?: 65535)
        val packetProcessor = PacketProcessor(config!!, this)
        
        try {
            while (running.get()) {
                buffer.clear()
                
                val length = inputStream.read(buffer.array())
                if (length > 0) {
                    buffer.limit(length)
                    
                    // Process the packet
                    val processedPackets = packetProcessor.processOutgoing(buffer.array().copyOf(length))
                    
                    for (packet in processedPackets) {
                        // Send modified packet
                        outputStream.write(packet)
                        bytesOut.addAndGet(packet.size.toLong())
                    }
                    
                    packetsProcessed.incrementAndGet()
                    
                    // Send stats update periodically
                    if (packetsProcessed.get() % 100 == 0L) {
                        sendStats()
                    }
                }
            }
        } catch (e: InterruptedException) {
            Log.i(TAG, "Packet processing interrupted")
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packets: ${e.message}", e)
            sendEvent("error", e.message)
        }
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SmartFox VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "SNI Spoofing VPN Service"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val stopIntent = Intent(this, SmartFoxVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SmartFox VPN Active")
            .setContentText("SNI Spoofing: ${config?.fakeSni ?: "Unknown"}")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_media_pause, "Stop", stopPendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
    
    private fun sendEvent(type: String, data: Any?) {
        try {
            MainActivity.instance?.runOnUiThread {
                eventSink?.success(mapOf(
                    "type" to type,
                    "data" to data
                ))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error sending event: ${e.message}")
        }
    }
    
    private fun sendStats() {
        sendEvent("stats", getStats())
    }
    
    override fun onRevoke() {
        Log.w(TAG, "VPN revoked by user")
        stopVpn()
        super.onRevoke()
    }
    
    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
