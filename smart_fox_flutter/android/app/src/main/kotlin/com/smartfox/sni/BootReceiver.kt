package com.smartfox.sni

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Boot receiver to optionally auto-start VPN on device boot
 */
class BootReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "SmartFoxBoot"
        private const val PREF_AUTO_START = "auto_start_on_boot"
    }
    
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED ||
            intent.action == "android.intent.action.QUICKBOOT_POWERON") {
            
            val prefs = context.getSharedPreferences("smart_fox_prefs", Context.MODE_PRIVATE)
            val autoStart = prefs.getBoolean(PREF_AUTO_START, false)
            
            if (autoStart) {
                Log.i(TAG, "Auto-starting VPN on boot...")
                
                // Get saved config
                val configJson = prefs.getString("last_config", null)
                if (configJson != null) {
                    // Note: In a production app, you'd parse the config and start the service
                    // For now, just log - user needs to manually start from app
                    Log.i(TAG, "Config found, but manual start required for security")
                }
            }
        }
    }
}
