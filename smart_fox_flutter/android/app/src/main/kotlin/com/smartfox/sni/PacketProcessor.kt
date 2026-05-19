package com.smartfox.sni

import android.net.VpnService
import android.util.Log
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import kotlin.random.Random

/**
 * Packet processor for SNI spoofing on Android
 * Handles TLS ClientHello modification and packet fragmentation
 */
class PacketProcessor(
    private val config: SmartFoxVpnService.VpnConfig,
    private val vpnService: VpnService
) {
    companion object {
        private const val TAG = "PacketProcessor"
        
        // IP Protocol numbers
        private const val IPPROTO_TCP = 6
        private const val IPPROTO_UDP = 17
        
        // TLS constants
        private const val TLS_HANDSHAKE = 0x16
        private const val TLS_CLIENT_HELLO = 0x01
        
        // TLS versions
        private val TLS_VERSION_10 = byteArrayOf(0x03, 0x01)
        private val TLS_VERSION_11 = byteArrayOf(0x03, 0x02)
        private val TLS_VERSION_12 = byteArrayOf(0x03, 0x03)
        private val TLS_VERSION_13 = byteArrayOf(0x03, 0x04)
        
        // Extension types
        private const val EXT_SNI = 0x0000
        private const val EXT_STATUS_REQUEST = 0x0005
        private const val EXT_SUPPORTED_GROUPS = 0x000A
        private const val EXT_EC_POINT_FORMATS = 0x000B
        private const val EXT_SIGNATURE_ALGORITHMS = 0x000D
        private const val EXT_ALPN = 0x0010
        private const val EXT_SIGNED_CERT_TIMESTAMP = 0x0012
        private const val EXT_PADDING = 0x0015
        private const val EXT_EXTENDED_MASTER_SECRET = 0x0017
        private const val EXT_SESSION_TICKET = 0x0023
        private const val EXT_SUPPORTED_VERSIONS = 0x002B
        private const val EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
        private const val EXT_KEY_SHARE = 0x0033
        private const val EXT_RENEGOTIATION_INFO = 0xFF01
    }
    
    /**
     * Process outgoing packets - intercept TLS ClientHello and modify SNI
     */
    fun processOutgoing(packet: ByteArray): List<ByteArray> {
        if (packet.size < 20) return listOf(packet) // Too small for IP header
        
        // Check IP version
        val version = (packet[0].toInt() and 0xF0) shr 4
        if (version != 4) return listOf(packet) // Only IPv4 for now
        
        // Get IP header length
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (packet.size < ihl + 20) return listOf(packet) // Too small for TCP header
        
        // Check protocol
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != IPPROTO_TCP) return listOf(packet) // Only TCP
        
        // Get destination port
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        
        // Only process HTTPS traffic (port 443)
        if (dstPort != 443) return listOf(packet)
        
        // Get TCP header length
        val tcpHeaderLen = ((packet[ihl + 12].toInt() and 0xF0) shr 4) * 4
        val payloadOffset = ihl + tcpHeaderLen
        
        if (packet.size <= payloadOffset) return listOf(packet) // No payload
        
        // Check for TLS ClientHello
        val payload = packet.copyOfRange(payloadOffset, packet.size)
        if (!isTlsClientHello(payload)) return listOf(packet)
        
        Log.d(TAG, "Detected TLS ClientHello, modifying SNI...")
        
        // Modify the ClientHello
        val modifiedPayload = modifyClientHello(payload)
        
        // Reassemble packet
        val modifiedPacket = ByteArray(payloadOffset + modifiedPayload.size)
        System.arraycopy(packet, 0, modifiedPacket, 0, payloadOffset)
        System.arraycopy(modifiedPayload, 0, modifiedPacket, payloadOffset, modifiedPayload.size)
        
        // Update IP total length
        val totalLength = modifiedPacket.size
        modifiedPacket[2] = ((totalLength shr 8) and 0xFF).toByte()
        modifiedPacket[3] = (totalLength and 0xFF).toByte()
        
        // Recalculate IP checksum
        recalculateIpChecksum(modifiedPacket, ihl)
        
        // Apply fragmentation if enabled
        if (config.enableFragmentation) {
            return fragmentPacket(modifiedPacket, payloadOffset)
        }
        
        return listOf(modifiedPacket)
    }
    
    private fun isTlsClientHello(payload: ByteArray): Boolean {
        if (payload.size < 6) return false
        
        // Check TLS record header
        if (payload[0].toInt() and 0xFF != TLS_HANDSHAKE) return false
        
        // Check handshake type
        if (payload[5].toInt() and 0xFF != TLS_CLIENT_HELLO) return false
        
        return true
    }
    
    private fun modifyClientHello(payload: ByteArray): ByteArray {
        try {
            // Find SNI extension and replace it
            val result = ByteArrayOutputStream()
            
            // Copy TLS record header (5 bytes)
            result.write(payload, 0, 5)
            
            // Process handshake message
            var offset = 5
            
            // Handshake type (1 byte)
            result.write(payload[offset++].toInt())
            
            // Handshake length (3 bytes) - will update later
            val handshakeLengthPos = result.size()
            result.write(payload, offset, 3)
            offset += 3
            
            // Client version (2 bytes)
            result.write(payload, offset, 2)
            offset += 2
            
            // Random (32 bytes)
            result.write(payload, offset, 32)
            offset += 32
            
            // Session ID
            val sessionIdLen = payload[offset].toInt() and 0xFF
            result.write(payload, offset, 1 + sessionIdLen)
            offset += 1 + sessionIdLen
            
            // Cipher suites
            val cipherSuitesLen = ((payload[offset].toInt() and 0xFF) shl 8) or (payload[offset + 1].toInt() and 0xFF)
            result.write(payload, offset, 2 + cipherSuitesLen)
            offset += 2 + cipherSuitesLen
            
            // Compression methods
            val compressionLen = payload[offset].toInt() and 0xFF
            result.write(payload, offset, 1 + compressionLen)
            offset += 1 + compressionLen
            
            // Extensions
            if (offset + 2 <= payload.size) {
                val extensionsLen = ((payload[offset].toInt() and 0xFF) shl 8) or (payload[offset + 1].toInt() and 0xFF)
                offset += 2
                
                val newExtensions = modifyExtensions(payload, offset, extensionsLen)
                
                // Write extensions length
                result.write((newExtensions.size shr 8) and 0xFF)
                result.write(newExtensions.size and 0xFF)
                result.write(newExtensions)
            }
            
            val finalPayload = result.toByteArray()
            
            // Update TLS record length
            val recordLength = finalPayload.size - 5
            finalPayload[3] = ((recordLength shr 8) and 0xFF).toByte()
            finalPayload[4] = (recordLength and 0xFF).toByte()
            
            // Update handshake length
            val handshakeLength = recordLength - 4
            finalPayload[handshakeLengthPos] = ((handshakeLength shr 16) and 0xFF).toByte()
            finalPayload[handshakeLengthPos + 1] = ((handshakeLength shr 8) and 0xFF).toByte()
            finalPayload[handshakeLengthPos + 2] = (handshakeLength and 0xFF).toByte()
            
            return finalPayload
            
        } catch (e: Exception) {
            Log.e(TAG, "Error modifying ClientHello: ${e.message}", e)
            return payload
        }
    }
    
    private fun modifyExtensions(payload: ByteArray, offset: Int, length: Int): ByteArray {
        val result = ByteArrayOutputStream()
        var pos = offset
        val endPos = offset + length
        
        while (pos + 4 <= endPos) {
            val extType = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
            val extLen = ((payload[pos + 2].toInt() and 0xFF) shl 8) or (payload[pos + 3].toInt() and 0xFF)
            
            if (extType == EXT_SNI) {
                // Replace SNI with fake SNI
                val sniExtension = buildSniExtension(config.fakeSni)
                result.write(sniExtension)
                Log.d(TAG, "Replaced SNI with: ${config.fakeSni}")
            } else {
                // Copy extension as-is
                result.write(payload, pos, 4 + extLen)
            }
            
            pos += 4 + extLen
        }
        
        return result.toByteArray()
    }
    
    private fun buildSniExtension(hostname: String): ByteArray {
        val hostnameBytes = hostname.toByteArray(Charsets.US_ASCII)
        val sniListLen = hostnameBytes.size + 3
        val extLen = sniListLen + 2
        
        val result = ByteArrayOutputStream()
        
        // Extension type (SNI = 0x0000)
        result.write(0x00)
        result.write(0x00)
        
        // Extension length
        result.write((extLen shr 8) and 0xFF)
        result.write(extLen and 0xFF)
        
        // SNI list length
        result.write((sniListLen shr 8) and 0xFF)
        result.write(sniListLen and 0xFF)
        
        // Host name type (0 = hostname)
        result.write(0x00)
        
        // Host name length
        result.write((hostnameBytes.size shr 8) and 0xFF)
        result.write(hostnameBytes.size and 0xFF)
        
        // Host name
        result.write(hostnameBytes)
        
        return result.toByteArray()
    }
    
    private fun fragmentPacket(packet: ByteArray, payloadOffset: Int): List<ByteArray> {
        val fragmentSize = if (config.randomizeFragments) {
            Random.nextInt(50, config.fragmentSize + 1)
        } else {
            config.fragmentSize
        }
        
        val payload = packet.copyOfRange(payloadOffset, packet.size)
        if (payload.size <= fragmentSize) {
            return listOf(packet)
        }
        
        val fragments = mutableListOf<ByteArray>()
        var offset = 0
        
        while (offset < payload.size) {
            val end = minOf(offset + fragmentSize, payload.size)
            val fragmentPayload = payload.copyOfRange(offset, end)
            
            // Create new packet with fragment
            val fragmentPacket = ByteArray(payloadOffset + fragmentPayload.size)
            System.arraycopy(packet, 0, fragmentPacket, 0, payloadOffset)
            System.arraycopy(fragmentPayload, 0, fragmentPacket, payloadOffset, fragmentPayload.size)
            
            // Update IP length
            val totalLen = fragmentPacket.size
            fragmentPacket[2] = ((totalLen shr 8) and 0xFF).toByte()
            fragmentPacket[3] = (totalLen and 0xFF).toByte()
            
            // Recalculate checksum
            val ihl = (fragmentPacket[0].toInt() and 0x0F) * 4
            recalculateIpChecksum(fragmentPacket, ihl)
            
            fragments.add(fragmentPacket)
            offset = end
        }
        
        Log.d(TAG, "Fragmented packet into ${fragments.size} parts")
        return fragments
    }
    
    private fun recalculateIpChecksum(packet: ByteArray, ihl: Int) {
        // Clear old checksum
        packet[10] = 0
        packet[11] = 0
        
        var sum = 0
        for (i in 0 until ihl step 2) {
            val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            sum += word
        }
        
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        
        val checksum = sum.inv() and 0xFFFF
        packet[10] = ((checksum shr 8) and 0xFF).toByte()
        packet[11] = (checksum and 0xFF).toByte()
    }
}
