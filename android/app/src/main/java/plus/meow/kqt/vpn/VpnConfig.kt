package plus.meow.kqt.vpn

import uniffi.kqt.SerializedRoute

/**
 * Configuration for a VPN tunnel.
 *
 * @property addresses IP addresses to assign to the VPN interface (e.g., "10.0.0.2/24")
 * @property routes List of routes to add to the VPN (using SerializedRoute from Rust backend)
 *                  SerializedRoute has fields: to (destination CIDR), via (gateway), metric (optional priority)
 * @property mtu Maximum transmission unit for the VPN interface (defaults to 1500)
 */
data class VpnConfig(
    val addresses: List<String> = emptyList(),
    val routes: List<SerializedRoute> = emptyList(),
    val mtu: Int = 1500
)

