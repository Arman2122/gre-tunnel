<div align="center">

# 🌐 GRE Tunnel Manager

**An intuitive bash script that simplifies creating and managing GRE (Generic Routing Encapsulation) tunnels on Linux systems**

![Version](https://img.shields.io/badge/version-2.2-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Shell](https://img.shields.io/badge/shell-Bash-orange.svg)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Options](#-options) • [Examples](#-examples) • [Contributing](#-contributing) • [Donations](#-donations)

---

</div>

## ✨ Features

<details>
<summary><b>Click to view all features</b></summary>

- 🚀 **Effortless Tunnel Creation** - Interactive wizard guides you through the process; no need to memorize commands
- 🌍 **IPv4 & IPv6 Support** - Full compatibility with both protocols; choose the one that fits your needs
- 🔄 **Intelligent IP Assignment** - Automated tunnel IP allocation handles the networking details for you
- 📊 **Real-Time Monitoring** - Comprehensive status tracking with live updates on all your tunnels
- 🔧 **Persistent Configuration** - Tunnels automatically restore after system reboots via systemd integration
- 🎯 **Flexible MTU Settings** - Configure anywhere from 68 to 9000 bytes with intelligent validation warnings
- 📈 **Traffic Analytics** - Monitor incoming and outgoing data flow through each tunnel interface
- 🏥 **Built-In Health Checks** - Integrated connectivity tests verify your tunnels are operational
- 💾 **JSON-Based Storage** - Clean, readable configuration format that's easy to back up and restore
- 🎨 **Polished CLI Interface** - Thoughtfully designed colorful output that enhances readability
- 🔍 **Comprehensive Diagnostics** - Detailed troubleshooting information helps you identify issues quickly
- 🛡️ **Robust Input Validation** - Prevents configuration errors before they cause problems
- 🔄 **Streamlined Management** - Modify or remove tunnels with minimal effort
- 📋 **Backup-Friendly Format** - JSON structure makes exporting and importing configurations straightforward

</details>

---

## 📋 Requirements

<details>
<summary><b>Click to expand system requirements</b></summary>

### Operating System
- Any modern **Linux** distribution is supported
- **systemd** is required (included by default in most modern distributions)

### Supported Distributions
- ✅ **Debian/Ubuntu** - thoroughly tested and verified
- ✅ **RHEL/CentOS/Fedora** - fully compatible
- ✅ **Arch Linux** - excellent support
- ✅ Other distributions are compatible as long as they include a compatible package manager

### Required Packages
No manual installation needed—the script automatically detects and installs any missing dependencies:

| Package | Purpose | Auto-installed |
|---------|---------|----------------|
| `iproute2` / `iproute` | Network interface management | ✅ |
| `systemd` | Service management | ✅ |
| `kmod` | Kernel module loading | ✅ |
| `iputils-ping` / `iputils` | Network connectivity testing | ✅ |
| `jq` | JSON configuration parsing | ✅ |
| `curl` | Optional - for public IP detection | ⚠️ |

### System Requirements
- **Root or sudo privileges** are required (necessary for network interface configuration)
- Kernel must support GRE modules (`ip_gre`, `ip6_gre`) - included by default in most Linux kernels
- Both servers must have **public IP addresses** and be able to communicate with each other

### Running the Script
```bash
# Execute with sudo privileges
sudo ./gre_setup_v2.sh
```

</details>

---

## 🚀 Installation

### Quick Install

```bash
# Download the script
wget https://raw.githubusercontent.com/Arman2122/gre_setup_v2.sh

# Grant execution permissions
chmod +x gre_setup_v2.sh

# Execute the script
sudo ./gre_setup_v2.sh
```

### System-Wide Installation (Optional)

For convenient access from any directory without specifying the full path:

```bash
# Put it in a system directory
sudo cp gre_setup_v2.sh /usr/local/sbin/gre-tunnel-manager
sudo chmod +x /usr/local/sbin/gre-tunnel-manager

# Now you can run it from anywhere
sudo gre-tunnel-manager
```

---

## 📖 Usage

### Basic Usage

```bash
sudo ./gre_setup_v2.sh
```

Simply execute the script and an interactive menu will appear. Select your desired option from the menu.

### First-Time Setup

Upon initial execution, the script will:
1. Verify required packages are installed and automatically install any missing dependencies
2. Initialize the configuration file if it doesn't already exist
3. Present the main menu—you're ready to begin!

---

## 🎯 Options

The main menu provides the following functionality:

### [1] 🚀 Create New Tunnel

An interactive wizard guides you through tunnel creation with these steps:

1. **Tunnel Name** - Assign a unique identifier such as `gre1` or `tunnel1`
2. **IP Version** - Choose between IPv4 or IPv6 according to your requirements
3. **Server Side** - Specify whether this is the Iran-side or External-side server
4. **Local IP** - Enter your server's public IP address (run `curl ifconfig.me` if uncertain)
5. **Remote IP** - Enter the remote server's public IP address
6. **Tunnel IP** - Choose one of two options:
   - Automatic assignment (recommended for simplicity)
   - Manual entry of a CIDR notation for custom network configuration
7. **MTU** - Maximum Transmission Unit defaults to 1470; adjust if you have specific requirements

**Auto-Assignment Mechanism:**
For **IPv4** (utilizes `/30` subnet):
  - Iran server receives `10.10.10.1/30`
  - External server receives `10.10.10.2/30`
  - Subsequent tunnels use `10.10.20.x`, `10.10.30.x`, incrementing by 10 each time

For **IPv6** (utilizes `/24` subnet):
  - Iran server receives `10.10.10.2/24`
  - External server receives `10.10.10.1/24`
  - Follows the same incremental pattern as IPv4

**Upon completion:**
- ✅ Tunnel interface is created and activated
- ✅ IP address is assigned to the interface
- ✅ MTU value is configured
- ✅ Configuration is persisted to `/etc/gre_tunnels.json`
- ✅ Systemd service is created and enabled for automatic startup
- ✅ Tunnel is operational and ready for use

---

### [2] 🗑️ Delete Tunnel

Remove an existing GRE tunnel from your system. You can select by number from the list or enter the tunnel name directly.

A confirmation prompt ensures you don't accidentally delete tunnels (safety first!).

**Components removed:**
- ✅ Tunnel network interface
- ✅ Associated systemd service
- ✅ Configuration entry

---

### [3] 🔄 Change Tunnel IP

Modify an existing tunnel's IP address configuration seamlessly.

**Capabilities:**
- Displays a selectable list of configured tunnels
- Validates CIDR format to prevent configuration errors
- Automatically updates the systemd service configuration
- Performs the change with minimal or zero downtime when executed correctly

**Procedure:**
1. Select the tunnel you wish to modify
2. Enter the new IP address with CIDR notation (e.g., `10.10.10.1/30`)
3. The script replaces the old IP with the new one
4. Configuration and service files are updated automatically

---

### [4] 📋 List Tunnels

View a comprehensive overview of all configured tunnels and their parameters:

**Information displayed:**
- Tunnel identifier name
- IP protocol version (IPv4 or IPv6)
- Server location (Iran or External)
- Local public IP address
- Remote public IP address
- Tunnel IP address with subnet mask
- Configured MTU value

---

### [5] 📊 Tunnel Status

Provides two levels of status information for monitoring your tunnels:

#### Overview
A high-level status summary across all tunnels:
- ✅ **UP & WORKING** - Tunnel is operational and functioning correctly
- ⚠️ **UP (no IP)** - Interface is active but lacks an IP address (configuration issue)
- ❌ **DOWN** - Tunnel interface is inactive
- ❌ **NOT FOUND** - Tunnel interface no longer exists in the system
- Systemd service status (active/enabled/inactive)
- Latency measurements via ping when available (IPv4 only)

#### Detailed Status
Select a specific tunnel for in-depth analysis:

**Configuration Details:**
- Complete tunnel settings including protocol version, server side, IP addresses, and MTU

**Interface Information:**
- Current operational state (up/down)
- Active MTU value in use
- Currently assigned IP address
- Remote peer IP address
- Warnings if configuration doesn't match actual state

**Traffic Statistics:**
- Received bytes (RX) with human-readable formatting
- Transmitted bytes (TX) with human-readable formatting
- Traffic activity indicators

**Connectivity Testing:**
- Automated ping test to remote tunnel endpoint (IPv4 only)
- Reachability status confirmation

**Systemd Service Status:**
- Current service state
- Boot-time auto-start configuration
- Error logs if service failures occur

---

### [6] ❓ Show Help

Need clarification on terminology or concepts? This section provides comprehensive guidance:

**Information provided:**
- Clear explanations of Local IP, Remote IP, and Tunnel IP addresses
- Detailed examples demonstrating auto-assignment behavior
- Proper formatting guidelines for manual IP address entry
- Listing of available network interfaces on your system
- Methods for discovering your server's public IP address

---

### [0] 🚪 Exit

Safely exits the program with a friendly message.

---

## 💡 Examples

### Example 1: Creating an IPv4 GRE Tunnel (Iran Server)

```
1. Tunnel Name: gre1
2. IP Version: IPv4
3. Server Side: Iran
4. Local IP: 185.123.45.67
5. Remote IP: 94.74.80.88
6. Tunnel IP: Auto-assign → 10.10.10.1/30
7. MTU: 1470
```

**On External Server:**
```
1. Tunnel Name: gre1
2. IP Version: IPv4
3. Server Side: External
4. Local IP: 94.74.80.88
5. Remote IP: 185.123.45.67
6. Tunnel IP: Manual → 10.10.10.2/30
7. MTU: 1470
```

### Example 2: Creating an IPv6 GRE Tunnel

```
1. Tunnel Name: gre61
2. IP Version: IPv6
3. Server Side: Iran
4. Local IP: 2001:db8::1
5. Remote IP: 2001:db8::2
6. Tunnel IP: Auto-assign → 10.10.10.2/24
7. MTU: 1470
```

### Example 3: Manual Tunnel IP Assignment

```
1. Tunnel Name: tunnel1
2. IP Version: IPv4
3. Server Side: External
4. Local IP: 192.0.2.1
5. Remote IP: 203.0.113.1
6. Tunnel IP: Manual → 172.16.1.1/30
7. MTU: 1400
```

---

## 📁 Configuration Files

### Main Configuration
- **Location**: `/etc/gre_tunnels.json`
- **Format**: JSON format for easy reading and manual editing
- **Permissions**: 600 (restricted to root user for security)
- **Structure**:
```json
{
  "tunnels": [
    {
      "tunnel": "gre1",
      "version": "4",
      "side": "iran",
      "local_ip": "185.123.45.67",
      "remote_ip": "94.74.80.88",
      "tunnel_ip": "10.10.10.1/30",
      "mtu": "1470"
    }
  ]
}
```

### Systemd Services
- **Location**: `/etc/systemd/system/gre-*.service`
- Each tunnel receives its own dedicated service file following the pattern `gre-<tunnel_name>.service`
- **Auto-start**: Enabled by default to ensure tunnels persist across reboots
- **Helper Script**: `/usr/local/sbin/gre-tunnel` (the underlying script that performs tunnel operations)

### Legacy Support
- The script maintains compatibility with legacy `/etc/gre_tunnels.conf` files, though JSON is now the standard format

---

## 🔧 Advanced Usage

### MTU Recommendations

| Scenario | Recommended MTU | Notes |
|----------|----------------|-------|
| Standard GRE | 1470 | Default, recommended for most cases |
| VPN over GRE | 1430-1440 | Account for VPN overhead |
| Low latency | 1200-1400 | Smaller packets, lower latency |
| High throughput | 1500 | Standard Ethernet MTU |
| Jumbo frames | 9000 | Requires all devices to support |

**MTU Validation:**
- Minimum: 68 bytes (Linux kernel's lower limit)
- Maximum: 9000 bytes (jumbo frames require hardware support throughout the network path)
- Warnings are displayed for non-standard values that may cause issues

### Backup Configuration

Regular backups are recommended for safety:

```bash
# Make a backup
sudo cp /etc/gre_tunnels.json ~/gre_tunnels_backup.json

# Restore it later (edit first if needed)
sudo cp ~/gre_tunnels_backup.json /etc/gre_tunnels.json
```

### Manual Tunnel Management

```bash
# Check tunnel status
ip link show gre1

# Check tunnel details
ip tunnel show gre1

# View traffic statistics
ip -s link show gre1

# Test connectivity (IPv4)
ping 10.10.10.2

# Check systemd service
systemctl status gre-gre1.service
```

---

## 🐛 Troubleshooting

### Common Issues

<details>
<summary><b>Tunnel won't come up</b></summary>

**Potential causes:**
- Firewall rules blocking GRE protocol (IP protocol 47)
- Incorrect local or remote IP addresses entered
- Network connectivity issues between the servers
- GRE kernel modules not loaded

**Troubleshooting steps:**
```bash
# Check kernel modules
lsmod | grep gre

# Load module manually
sudo modprobe ip_gre  # for IPv4
sudo modprobe ip6_gre # for IPv6

# Check firewall
sudo iptables -L -n -v | grep 47

# Test connectivity
ping -c 3 <remote_ip>
```
</details>

<details>
<summary><b>Configuration file errors</b></summary>

**Identifying symptoms:**
- Script reports inability to read the configuration file
- Tunnels are lost after system reboot

**Resolution steps:**
```bash
# Check file permissions
ls -l /etc/gre_tunnels.json

# Fix permissions
sudo chmod 600 /etc/gre_tunnels.json

# Validate JSON syntax
jq . /etc/gre_tunnels.json
```
</details>

<details>
<summary><b>Systemd service not starting</b></summary>

**Check service status:**
```bash
systemctl status gre-<tunnel_name>.service
journalctl -u gre-<tunnel_name>.service
```

**Recommended solutions:**
- Verify that network-online.target is available (typically present by default)
- Verify helper script permissions: `ls -l /usr/local/sbin/gre-tunnel`
- Validate JSON syntax integrity: `jq . /etc/gre_tunnels.json`
</details>

<details>
<summary><b>Cannot ping remote tunnel IP</b></summary>

**Verification checklist:**
1. Both tunnel endpoints have matching tunnel IP addresses configured
2. The remote server's tunnel interface is actually active
3. Firewall rules are not blocking ICMP/ping traffic
4. MTU values match on both tunnel endpoints
5. Routing tables are configured correctly
</details>

---

## 🤝 Contributing

We welcome and appreciate contributions! If you see room for improvement, feel free to enhance the project.


**We appreciate your contributions!** 🙏

---

## 💰 Donations

If this project has been valuable to you, we'd be grateful for your support. Donations help ensure continued maintenance and feature development.

### Cryptocurrency Donations

#### Bitcoin (BTC)
```
bc1qmany8ax0kfk9k3xzhcccvj3242rmt0rzd7dskx
```

#### Ethereum (ETH) / USDT (ERC-20)
```
0x6d45285d14f73b04048ab66Ab56b466d65F10E11
```

#### TRON (TRX) / USDT (TRC-20)
```
TFx8iyBrYZKfC7iKLsgsFiBdU3jQps7m5g
```

#### BNB - BNB Smart Chain
```
bnb1v3frnlyycw5k2lvk6wv9glg99dhmcsylp4lyyn
```

**We truly appreciate your support!** Every contribution, regardless of size, makes a meaningful difference. 🙏

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

<div align="center">

**⭐ If you found this project helpful, we'd love your support with a star! ⭐**

Made with ❤️ by Arman2122

</div>
