#!/bin/bash
# GRE Tunnel Manager - IPv4 & IPv6
# Author: Arman2122

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)" >&2
    exit 1
fi

CONFIG_FILE="/etc/gre_tunnels.json"
CONFIG_FILE_OLD="/etc/gre_tunnels.conf"
AUTHOR="Arman2122"

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
WHITE="\e[37m"
BOLD="\e[1m"
DIM="\e[2m"
RESET="\e[0m"

SYSTEMD_DIR="/etc/systemd/system"
SERVICE_PREFIX="gre-"
HELPER_SCRIPT="/usr/local/sbin/gre-tunnel"

BG_RED="\e[41m"
BG_GREEN="\e[42m"
BG_YELLOW="\e[43m"
BG_BLUE="\e[44m"

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION_ID="$VERSION_ID"
    elif [[ -f /etc/debian_version ]]; then
        OS_ID="debian"
        OS_VERSION_ID=$(cat /etc/debian_version)
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="rhel"
        OS_VERSION_ID=$(cat /etc/redhat-release)
    else
        OS_ID="unknown"
        OS_VERSION_ID="unknown"
    fi
}

check_dependencies() {
    local missing_pkgs=()
    local pkg_manager=""
    local update_cmd=""
    local install_cmd=""
    
    detect_os
    
    # Determine package manager
    if command -v apt-get >/dev/null 2>&1; then
        pkg_manager="apt-get"
        update_cmd="apt-get update -qq"
        install_cmd="apt-get install -y -qq"
    elif command -v yum >/dev/null 2>&1; then
        pkg_manager="yum"
        update_cmd="true"
        install_cmd="yum install -y -q"
    elif command -v dnf >/dev/null 2>&1; then
        pkg_manager="dnf"
        update_cmd="true"
        install_cmd="dnf install -y -q"
    elif command -v pacman >/dev/null 2>&1; then
        pkg_manager="pacman"
        update_cmd="pacman -Sy --noconfirm"
        install_cmd="pacman -S --noconfirm --needed"
    else
        echo -e "${RED}❌ Error: Could not detect package manager.${RESET}" >&2
        echo -e "${YELLOW}   Please install required packages manually: iproute2, systemd, kmod, iputils-ping, jq${RESET}" >&2
        return 1
    fi
    
    # Check required commands and map to packages
    if ! command -v ip >/dev/null 2>&1; then
        if [[ "$pkg_manager" == "apt-get" ]]; then
            missing_pkgs+=("iproute2")
        elif [[ "$pkg_manager" == "yum" ]] || [[ "$pkg_manager" == "dnf" ]]; then
            missing_pkgs+=("iproute")
        elif [[ "$pkg_manager" == "pacman" ]]; then
            missing_pkgs+=("iproute2")
        fi
    fi
    
    if ! command -v systemctl >/dev/null 2>&1; then
        if [[ "$pkg_manager" == "apt-get" ]]; then
            missing_pkgs+=("systemd")
        elif [[ "$pkg_manager" == "yum" ]] || [[ "$pkg_manager" == "dnf" ]]; then
            missing_pkgs+=("systemd")
        elif [[ "$pkg_manager" == "pacman" ]]; then
            missing_pkgs+=("systemd")
        fi
    fi
    
    if ! command -v modprobe >/dev/null 2>&1; then
        if [[ "$pkg_manager" == "apt-get" ]]; then
            missing_pkgs+=("kmod")
        elif [[ "$pkg_manager" == "yum" ]] || [[ "$pkg_manager" == "dnf" ]]; then
            missing_pkgs+=("kmod")
        elif [[ "$pkg_manager" == "pacman" ]]; then
            missing_pkgs+=("kmod")
        fi
    fi
    
    if ! command -v ping >/dev/null 2>&1; then
        if [[ "$pkg_manager" == "apt-get" ]]; then
            missing_pkgs+=("iputils-ping")
        elif [[ "$pkg_manager" == "yum" ]] || [[ "$pkg_manager" == "dnf" ]]; then
            missing_pkgs+=("iputils")
        elif [[ "$pkg_manager" == "pacman" ]]; then
            missing_pkgs+=("iputils")
        fi
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        missing_pkgs+=("jq")
    fi
    
    # Optional but recommended
    if ! command -v curl >/dev/null 2>&1; then
        missing_pkgs+=("curl")
    fi
    
    # Install missing packages
    if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Missing dependencies detected. Installing...${RESET}"
        echo -e "${DIM}   Packages needed: ${missing_pkgs[*]}${RESET}"
        
        # Update package list
        eval "$update_cmd" >/dev/null 2>&1
        
        # Install packages
        if eval "$install_cmd ${missing_pkgs[*]}" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Dependencies installed successfully!${RESET}"
        else
            echo -e "${RED}❌ Error: Failed to install dependencies.${RESET}" >&2
            echo -e "${YELLOW}   Please install manually: ${missing_pkgs[*]}${RESET}" >&2
            return 1
        fi
    fi
    
    # Verify critical commands
    if ! command -v ip >/dev/null 2>&1 || ! command -v systemctl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        echo -e "${RED}❌ Error: Critical dependencies are still missing after installation.${RESET}" >&2
        return 1
    fi
    
    return 0
}

init_json_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo '{"tunnels":[]}' > "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
    fi
}

get_all_tunnels() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        return 1
    fi
    
    jq -c '.tunnels[]' "$CONFIG_FILE" 2>/dev/null
}

get_tunnel_by_name() {
    local tunnel_name="$1"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        return 1
    fi
    
    jq -c ".tunnels[] | select(.tunnel == \"$tunnel_name\")" "$CONFIG_FILE" 2>/dev/null
}

tunnel_exists() {
    local tunnel_name="$1"
    local count=$(jq -r "[.tunnels[] | select(.tunnel == \"$tunnel_name\")] | length" "$CONFIG_FILE" 2>/dev/null)
    [[ "$count" -gt 0 ]] && return 0 || return 1
}

add_tunnel_to_json() {
    local tunnel="$1"
    local version="$2"
    local side="$3"
    local local_ip="$4"
    local remote_ip="$5"
    local tunnel_ip="$6"
    local mtu="$7"
    
    init_json_config
    
    local new_tunnel=$(jq -n \
        --arg t "$tunnel" \
        --arg v "$version" \
        --arg s "$side" \
        --arg l "$local_ip" \
        --arg r "$remote_ip" \
        --arg ti "$tunnel_ip" \
        --arg m "$mtu" \
        '{tunnel: $t, version: $v, side: $s, local_ip: $l, remote_ip: $r, tunnel_ip: $ti, mtu: $m}')
    
    jq ".tunnels += [$new_tunnel]" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && \
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

remove_tunnel_from_json() {
    local tunnel_name="$1"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        return 1
    fi
    
    jq "del(.tunnels[] | select(.tunnel == \"$tunnel_name\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && \
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

update_tunnel_ip_in_json() {
    local tunnel_name="$1"
    local new_ip="$2"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        return 1
    fi
    
    jq "(.tunnels[] | select(.tunnel == \"$tunnel_name\") | .tunnel_ip) = \"$new_ip\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && \
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

banner() {
    clear
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}                     ${BOLD}${WHITE}GRE Tunnel Manager${RESET}                       ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}                        ${DIM}Version 2.1${RESET}                          ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}                      ${DIM}Author: ${AUTHOR}${RESET}                       ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo
}

show_help() {
    echo -e "${BOLD}${YELLOW}📋 Help & Examples:${RESET}"
    echo -e "${DIM}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${DIM}│${RESET} ${CYAN}• Local IP:${RESET} Your server's public IP address"
    echo -e "${DIM}│${RESET} ${CYAN}• Remote IP:${RESET} The other server's public IP address"
    echo -e "${DIM}│${RESET} ${CYAN}• Tunnel IP:${RESET} ${GREEN}Choose auto-assign or manual input${RESET}"
    echo -e "${DIM}│${RESET}"
    echo -e "${DIM}│${RESET} ${BOLD}${YELLOW}Auto-assign (Recommended):${RESET}"
    echo -e "${DIM}│${RESET}   ${BOLD}IPv4 GRE Tunnels (/30 subnet):${RESET}"
    echo -e "${DIM}│${RESET}     - Iran server: 10.10.10.1/30"
    echo -e "${DIM}│${RESET}     - External server: 10.10.10.2/30"
    echo -e "${DIM}│${RESET}   ${BOLD}IPv6 GRE Tunnels (/24 subnet):${RESET}"
    echo -e "${DIM}│${RESET}     - Iran server: 10.10.10.2/24"
    echo -e "${DIM}│${RESET}     - External server: 10.10.10.1/24"
    echo -e "${DIM}│${RESET}"
    echo -e "${DIM}│${RESET} ${BOLD}${YELLOW}Manual Input:${RESET}"
    echo -e "${DIM}│${RESET}   - Enter any valid CIDR notation"
    echo -e "${DIM}│${RESET}   - Examples: 192.168.1.1/30, 172.16.1.1/24"
    echo -e "${DIM}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo
}

get_network_interfaces() {
    echo -e "${BOLD}${BLUE}🌐 Available Network Interfaces:${RESET}"
    ip -o link show | awk -F': ' '{print "  " $2}' | grep -v lo
    echo
}

show_public_ip_help() {
    echo -e "${BOLD}${BLUE}🌍 Public IP Information:${RESET}"
    echo -e "   ${DIM}You can find your public IP using:${RESET}"
    echo -e "   ${DIM}• curl ifconfig.me${RESET}"
    echo -e "   ${DIM}• curl ipinfo.io/ip${RESET}"
    echo -e "   ${DIM}• Check your server provider's control panel${RESET}"
    echo
}

ensure_helper_script() {
	if [[ ! -x "$HELPER_SCRIPT" ]]; then
		cat > "$HELPER_SCRIPT" << 'EOF'
#!/bin/bash
# gre-tunnel helper: idempotently create/start or stop a GRE tunnel
# Author: Arman2122 (GitHub: https://github.com/Arman2122)
# Usage:
#   gre-tunnel up   <tunnel> <version> <side> <local_ip> <remote_ip> <tunnel_cidr> <mtu>
#   gre-tunnel down <tunnel>

set -euo pipefail

action=${1:-}
if [[ "$action" == "up" ]]; then
	if [[ $# -ne 8 ]]; then
		echo "Usage: $0 up <tunnel> <version> <side> <local_ip> <remote_ip> <tunnel_cidr> <mtu>" >&2
		exit 1
	fi
	tunnel="$2"
	version="$3"
	# side is not strictly needed here, accepted for parity
	local_ip="$5"
	remote_ip="$6"
	tunnel_cidr="$7"
	mtu="$8"

	# Load required kernel module
	if [[ "$version" == "6" ]]; then
		/sbin/modprobe ip6_gre || true
	else
		/sbin/modprobe ip_gre || true
	fi

	# Create tunnel if not exists
	if ip link show "$tunnel" >/dev/null 2>&1; then
		:
	else
		if [[ "$version" == "6" ]]; then
			/sbin/ip -6 tunnel add "$tunnel" mode ip6gre local "$local_ip" remote "$remote_ip" ttl 255
		else
			/sbin/ip tunnel add "$tunnel" mode gre local "$local_ip" remote "$remote_ip" ttl 255
		fi
	fi

	# Ensure address, mtu, and up state are correct (idempotent)
	# Check if address already exists, if not add it
	tunnel_ip=$(echo "$tunnel_cidr" | cut -d'/' -f1)
	if ! /sbin/ip addr show dev "$tunnel" | grep -qFw "$tunnel_ip"; then
		/sbin/ip addr add "$tunnel_cidr" dev "$tunnel"
	fi
	/sbin/ip link set "$tunnel" mtu "$mtu" || true
	/sbin/ip link set "$tunnel" up

elif [[ "$action" == "down" ]]; then
	if [[ $# -ne 2 ]]; then
		echo "Usage: $0 down <tunnel>" >&2
		exit 1
	fi
	tunnel="$2"
	/sbin/ip link set "$tunnel" down 2>/dev/null || true
	/sbin/ip tunnel del "$tunnel" 2>/dev/null || true
else
	echo "Unknown action: $action" >&2
	exit 1
fi
EOF
		chmod +x "$HELPER_SCRIPT"
	fi
}

create_systemd_service() {
	local tunnel="$1"
	local version="$2"
	local side="$3"
	local local_ip="$4"
	local remote_ip="$5"
	local tunnel_ip="$6"
	local mtu="$7"

	ensure_helper_script

	local unit_name="${SERVICE_PREFIX}${tunnel}.service"
	local unit_path="${SYSTEMD_DIR}/${unit_name}"

 cat > "$unit_path" << EOF
# GRE Tunnel Unit: ${tunnel}
# Author: ${AUTHOR}
[Unit]
Description=GRE Tunnel ${tunnel}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${HELPER_SCRIPT} up ${tunnel} ${version} ${side} ${local_ip} ${remote_ip} ${tunnel_ip} ${mtu}
ExecStop=${HELPER_SCRIPT} down ${tunnel}
Restart=no

[Install]
WantedBy=multi-user.target
EOF

	systemctl daemon-reload
	# enable for startup and start now without failing if already up
	systemctl enable "$unit_name" >/dev/null 2>&1 || true
	# start now; helper is idempotent
	systemctl start "$unit_name" >/dev/null 2>&1 || true
}

remove_systemd_service() {
	local tunnel="$1"
	local unit_name="${SERVICE_PREFIX}${tunnel}.service"
	local unit_path="${SYSTEMD_DIR}/${unit_name}"

	if systemctl list-units --all | grep -q "${unit_name}"; then
		systemctl stop "$unit_name" >/dev/null 2>&1 || true
		systemctl disable "$unit_name" >/dev/null 2>&1 || true
	fi
	if [[ -f "$unit_path" ]]; then
		rm -f "$unit_path"
		systemctl daemon-reload
	fi
}

validate_ip() {
    local ip=$1
    local version=$2  # optional: "4" or "6"
    
    if [[ -z "$version" ]]; then
        if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            IFS='.' read -ra ADDR <<< "$ip"
            for octet in "${ADDR[@]}"; do
                if [[ $octet -lt 0 || $octet -gt 255 ]]; then
                    return 1
                fi
            done
            return 0
        fi
        if command -v ip >/dev/null 2>&1; then
            if ip -6 route get "$ip" >/dev/null 2>&1; then
                return 0
            fi
        fi
        return 1
    elif [[ "$version" == "4" ]]; then
        if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            IFS='.' read -ra ADDR <<< "$ip"
            for octet in "${ADDR[@]}"; do
                if [[ $octet -lt 0 || $octet -gt 255 ]]; then
                    return 1
                fi
            done
            return 0
        fi
        return 1
    elif [[ "$version" == "6" ]]; then
        if command -v ip >/dev/null 2>&1; then
            if ip -6 route get "$ip" >/dev/null 2>&1; then
                return 0
            fi
        fi
        if [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]] || \
           [[ $ip =~ ^::1$ ]] || \
           [[ $ip =~ ^::$ ]] || \
           [[ $ip =~ ^[0-9a-fA-F]{0,4}::[0-9a-fA-F]{0,4}$ ]] || \
           [[ $ip =~ ^([0-9a-fA-F]{0,4}:)+::([0-9a-fA-F]{0,4}:)*[0-9a-fA-F]{0,4}$ ]] || \
           [[ $ip =~ ^::([0-9a-fA-F]{0,4}:)*[0-9a-fA-F]{0,4}$ ]] || \
           [[ $ip =~ ^([0-9a-fA-F]{0,4}:)+::$ ]]; then
            local colon_count=$(echo "$ip" | tr -cd ':' | wc -c)
            if [[ $colon_count -ge 1 && $colon_count -le 7 ]]; then
                return 0
            fi
        fi
        return 1
    fi
    return 1
}

validate_cidr() {
    local cidr=$1
    local version=$2  # optional: "4" or "6"
    
    if [[ ! "$cidr" =~ / ]]; then
        return 1
    fi
    
    local ip_part=$(echo "$cidr" | cut -d'/' -f1)
    local prefix_part=$(echo "$cidr" | cut -d'/' -f2)
    
    if [[ -z "$version" ]]; then
        if [[ $cidr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            if validate_ip "$ip_part" "4" && [[ $prefix_part -ge 0 && $prefix_part -le 32 ]]; then
                return 0
            fi
        fi
        if validate_ip "$ip_part" "6" && [[ $prefix_part =~ ^[0-9]+$ ]] && [[ $prefix_part -ge 0 && $prefix_part -le 128 ]]; then
            return 0
        fi
        return 1
    elif [[ "$version" == "4" ]]; then
        if [[ $cidr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            if validate_ip "$ip_part" "4" && [[ $prefix_part -ge 0 && $prefix_part -le 32 ]]; then
                return 0
            fi
        fi
        return 1
    elif [[ "$version" == "6" ]]; then
        if validate_ip "$ip_part" "6" && [[ $prefix_part =~ ^[0-9]+$ ]] && [[ $prefix_part -ge 0 && $prefix_part -le 128 ]]; then
            return 0
        fi
        return 1
    fi
    return 1
}

# validate MTU value
validate_mtu() {
    local mtu=$1
    local show_tips=${2:-true}
    
    if ! [[ "$mtu" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}❌ Invalid MTU. Must be a number.${RESET}"
        return 1
    fi
    
    # check absolute limits (Linux kernel supports 68-9000)
    if [[ $mtu -lt 68 ]]; then
        echo -e "${RED}❌ MTU too low! Minimum is 68 bytes.${RESET}"
        echo -e "${YELLOW}   💡 MTU below 68 is not supported by Linux kernel.${RESET}"
        return 1
    fi
    
    if [[ $mtu -gt 9000 ]]; then
        echo -e "${RED}❌ MTU too high! Maximum is 9000 bytes (jumbo frames).${RESET}"
        echo -e "${YELLOW}   💡 Most network equipment doesn't support MTU above 9000.${RESET}"
        return 1
    fi
    
    if [[ "$show_tips" == "true" ]]; then
        if [[ $mtu -lt 576 ]]; then
            echo -e "${YELLOW}⚠️  Very low MTU detected ($mtu bytes)${RESET}"
            echo -e "${YELLOW}   💡 Standard minimum IP MTU is 576 bytes. Lower values may cause:${RESET}"
            echo -e "${YELLOW}      • Excessive packet fragmentation${RESET}"
            echo -e "${YELLOW}      • Reduced network efficiency${RESET}"
            echo -e "${YELLOW}      • Performance degradation${RESET}"
        elif [[ $mtu -ge 576 && $mtu -lt 1200 ]]; then
            echo -e "${YELLOW}⚠️  Low MTU value ($mtu bytes)${RESET}"
            echo -e "${YELLOW}   💡 Consider using MTU between 1200-1500 for better performance.${RESET}"
            echo -e "${YELLOW}      Standard MTU for GRE tunnels is 1470 (recommended).${RESET}"
        elif [[ $mtu -gt 1500 && $mtu -le 9000 ]]; then
            echo -e "${YELLOW}⚠️  High MTU value ($mtu bytes)${RESET}"
            echo -e "${YELLOW}   💡 MTU above 1500 requires jumbo frame support:${RESET}"
            echo -e "${YELLOW}      • All network devices in path must support jumbo frames${RESET}"
            echo -e "${YELLOW}      • Standard Ethernet MTU is 1500 bytes${RESET}"
            echo -e "${YELLOW}      • May cause fragmentation if not supported${RESET}"
            if [[ $mtu -gt 1500 && $mtu -lt 9000 ]]; then
                echo -e "${YELLOW}      • Ensure remote peer and all intermediate devices support this MTU${RESET}"
            fi
        fi
    fi
    
    return 0
}

check_tunnel_status() {
    local tunnel="$1"
    
    if ! ip link show "$tunnel" >/dev/null 2>&1; then
        echo "NOT_FOUND"
        return
    fi

    local link_output=$(ip link show "$tunnel" 2>/dev/null)
    
    if echo "$link_output" | grep -qE '<.*(UP|LOWER_UP).*>'; then
        if ip addr show dev "$tunnel" 2>/dev/null | grep -q "inet"; then
            echo "UP"
        else
            echo "UP_NO_IP"
        fi
    else
        echo "DOWN"
    fi
}

# get ping
get_ping_time() {
    local tunnel_ip="$1"
    local version="$2"
    
    if [[ "$version" != "4" ]]; then
        echo ""
        return
    fi
    
    local tunnel_ip_only=$(echo "$tunnel_ip" | cut -d'/' -f1)
    local ip_octets=($(echo "$tunnel_ip_only" | tr '.' ' '))
    local remote_tunnel_ip=""
    
    if [[ "${ip_octets[3]}" == "1" ]]; then
        remote_tunnel_ip="${ip_octets[0]}.${ip_octets[1]}.${ip_octets[2]}.2"
    else
        remote_tunnel_ip="${ip_octets[0]}.${ip_octets[1]}.${ip_octets[2]}.1"
    fi
    
    local ping_result=$(ping -c 1 -W 2 "$remote_tunnel_ip" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        local ping_time=$(echo "$ping_result" | grep -oE 'time=[0-9.]+[[:space:]]*ms|[0-9.]+[[:space:]]*ms' | head -1)
        if [[ -n "$ping_time" ]]; then
            local ping_value=$(echo "$ping_time" | grep -oE '[0-9.]+' | head -1)
            if [[ -n "$ping_value" ]]; then
                local ping_ms=$(echo "$ping_value" | awk '{printf "%.0f", $1}')
                echo "${ping_ms} ms"
            else
                echo ""
            fi
        else
            echo ""
        fi
    else
        echo ""
    fi
}

list_tunnels() {
    banner
    echo -e "${BOLD}${YELLOW}📋 Configured Tunnels:${RESET}"
    echo -e "${DIM}┌─────────────────────────────────────────────────────────────┐${RESET}"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        local count=0
        while IFS= read -r tunnel_json; do
            [[ -z "$tunnel_json" ]] && continue
            ((count++))
            local tunnel=$(echo "$tunnel_json" | jq -r '.tunnel')
            local version=$(echo "$tunnel_json" | jq -r '.version')
            local side=$(echo "$tunnel_json" | jq -r '.side')
            local local_ip=$(echo "$tunnel_json" | jq -r '.local_ip')
            local remote_ip=$(echo "$tunnel_json" | jq -r '.remote_ip')
            local tunnel_ip=$(echo "$tunnel_json" | jq -r '.tunnel_ip')
            local mtu=$(echo "$tunnel_json" | jq -r '.mtu')
            
            echo -e "${DIM}│${RESET} ${BOLD}${CYAN}Tunnel #$count:${RESET} $tunnel"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Type: IPv$version GRE"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Side: $side"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Local IP: $local_ip"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Remote IP: $remote_ip"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Tunnel IP: $tunnel_ip"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} MTU: $mtu"
            echo -e "${DIM}│${RESET}"
        done < <(get_all_tunnels)
        
        if [[ $count -eq 0 ]]; then
            echo -e "${DIM}│${RESET} ${YELLOW}No tunnels configured yet.${RESET}"
        fi
    else
        echo -e "${DIM}│${RESET} ${YELLOW}No tunnels configured yet.${RESET}"
    fi
    
    echo -e "${DIM}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo
}

show_tunnel_status() {
    banner
    echo -e "${BOLD}${CYAN}📊 Tunnel Status & Details${RESET}"
    echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"
    echo

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${YELLOW}⚠️  No tunnels configured yet.${RESET}"
        echo
        return
    fi
    
    local tunnel_count=$(jq -r '.tunnels | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
    if [[ "$tunnel_count" == "0" ]]; then
        echo -e "${YELLOW}⚠️  No tunnels configured yet.${RESET}"
        echo
        return
    fi

    # show all tunnels status overview
    echo -e "${BOLD}${YELLOW}📋 All Tunnels Overview:${RESET}"
    echo -e "${DIM}┌─────────────────────────────────────────────────────────────┐${RESET}"
    
    local count=0
    local tunnels=()
    while IFS= read -r tunnel_json; do
        [[ -z "$tunnel_json" ]] && continue
        ((count++))
        local tunnel=$(echo "$tunnel_json" | jq -r '.tunnel')
        local version=$(echo "$tunnel_json" | jq -r '.version')
        local tunnel_ip=$(echo "$tunnel_json" | jq -r '.tunnel_ip')
        tunnels+=("$tunnel")
        
        local tunnel_status=$(check_tunnel_status "$tunnel")
        case "$tunnel_status" in
            "UP")
                local status_icon="${GREEN}✓${RESET}"
                local status_text="${GREEN}UP & WORKING${RESET}"
                ;;
            "UP_NO_IP")
                local status_icon="${YELLOW}⚠${RESET}"
                local status_text="${YELLOW}UP (no IP)${RESET}"
                ;;
            "DOWN")
                local status_icon="${RED}✗${RESET}"
                local status_text="${RED}DOWN${RESET}"
                ;;
            "NOT_FOUND")
                local status_icon="${RED}✗${RESET}"
                local status_text="${RED}NOT FOUND${RESET}"
                ;;
        esac
        
        # check systemd service status
        local unit_name="${SERVICE_PREFIX}${tunnel}.service"
        local svc_status="N/A"
        if systemctl list-units --all | grep -q "${unit_name}"; then
            if systemctl is-active --quiet "${unit_name}" 2>/dev/null; then
                svc_status="${GREEN}active${RESET}"
            elif systemctl is-enabled --quiet "${unit_name}" 2>/dev/null; then
                svc_status="${YELLOW}enabled${RESET}"
            else
                svc_status="${RED}inactive${RESET}"
            fi
        fi
        
        # get ping time
        local ping_info=""
        if [[ "$tunnel_status" == "UP" ]]; then
            local ping_time=$(get_ping_time "$tunnel_ip" "$version")
            if [[ -n "$ping_time" ]]; then
                ping_info=" | ${DIM}Ping:${RESET} ${GREEN}${ping_time}${RESET}"
            fi
        fi
        
        echo -e "${DIM}│${RESET} ${status_icon} ${BOLD}${CYAN}[$count]${RESET} ${CYAN}$tunnel${RESET}"
        echo -e "${DIM}│${RESET}    ${DIM}Status:${RESET} $status_text | ${DIM}Service:${RESET} $svc_status${ping_info}"
        echo -e "${DIM}│${RESET}"
    done < <(get_all_tunnels)
    
    echo -e "${DIM}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo

    # detailed view option
    if [[ $count -eq 0 ]]; then
        return
    fi

    echo -e "${BOLD}${YELLOW}Select tunnel for detailed status:${RESET}"
    echo -e "${DIM}Enter tunnel number [1-$count] or 'a' for all, '0' to skip:${RESET}"
    read -p "   Your choice: " selection

    if [[ "$selection" == "0" ]]; then
        return
    fi

    if [[ "$selection" == "a" || "$selection" == "A" ]]; then
        # show all tunnels in detail
        local idx=0
        while IFS= read -r tunnel_json; do
            [[ -z "$tunnel_json" ]] && continue
            ((idx++))
            local tunnel=$(echo "$tunnel_json" | jq -r '.tunnel')
            local version=$(echo "$tunnel_json" | jq -r '.version')
            local side=$(echo "$tunnel_json" | jq -r '.side')
            local local_ip=$(echo "$tunnel_json" | jq -r '.local_ip')
            local remote_ip=$(echo "$tunnel_json" | jq -r '.remote_ip')
            local tunnel_ip=$(echo "$tunnel_json" | jq -r '.tunnel_ip')
            local mtu=$(echo "$tunnel_json" | jq -r '.mtu')
            
            show_detailed_tunnel_status "$tunnel" "$version" "$side" "$local_ip" "$remote_ip" "$tunnel_ip" "$mtu"
            if [[ $idx -lt $count ]]; then
                echo
                echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"
                echo
            fi
        done < <(get_all_tunnels)
    elif [[ "$selection" =~ ^[0-9]+$ ]]; then
        if [[ $selection -ge 1 && $selection -le $count ]]; then
            TUNNEL="${tunnels[$((selection-1))]}"
            local tunnel_json=$(get_tunnel_by_name "$TUNNEL")
            if [[ -n "$tunnel_json" ]]; then
                CURRENT_VERSION=$(echo "$tunnel_json" | jq -r '.version')
                CURRENT_SIDE=$(echo "$tunnel_json" | jq -r '.side')
                CURRENT_LOCAL_IP=$(echo "$tunnel_json" | jq -r '.local_ip')
                CURRENT_REMOTE_IP=$(echo "$tunnel_json" | jq -r '.remote_ip')
                CURRENT_TUNNEL_IP=$(echo "$tunnel_json" | jq -r '.tunnel_ip')
                CURRENT_MTU=$(echo "$tunnel_json" | jq -r '.mtu')
                
                show_detailed_tunnel_status "$TUNNEL" "$CURRENT_VERSION" "$CURRENT_SIDE" "$CURRENT_LOCAL_IP" "$CURRENT_REMOTE_IP" "$CURRENT_TUNNEL_IP" "$CURRENT_MTU"
            fi
        else
            echo -e "${RED}❌ Invalid selection.${RESET}"
        fi
    else
        echo -e "${RED}❌ Invalid selection.${RESET}"
    fi
    echo
}

show_detailed_tunnel_status() {
    local tunnel="$1"
    local version="$2"
    local side="$3"
    local local_ip="$4"
    local remote_ip="$5"
    local tunnel_ip="$6"
    local mtu="$7"

    echo -e "${BOLD}${CYAN}🔍 Detailed Status: ${WHITE}$tunnel${RESET}"
    echo -e "${DIM}┌─────────────────────────────────────────────────────────────┐${RESET}"
    
    # configuration info
    echo -e "${DIM}│${RESET} ${BOLD}${YELLOW}Configuration:${RESET}"
    echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Type: IPv$version GRE"
    echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Side: $side"
    echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Local IP: $local_ip"
    echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Remote IP: $remote_ip"
    echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Tunnel IP: $tunnel_ip"
    echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} MTU: $mtu"
    echo -e "${DIM}│${RESET}"
    
    # interface status
    echo -e "${DIM}│${RESET} ${BOLD}${YELLOW}Interface Status:${RESET}"
    local tunnel_status=$(check_tunnel_status "$tunnel")
    if [[ "$tunnel_status" != "NOT_FOUND" ]]; then
        local mtu_actual=$(ip link show "$tunnel" | grep -o 'mtu [0-9]*' | awk '{print $2}' | head -1)
        local state_raw=$(ip link show "$tunnel" | grep -o 'state [A-Z]*' | awk '{print $2}' | head -1)
        
        case "$tunnel_status" in
            "UP")
                echo -e "${DIM}│${RESET}   ${GREEN}✓${RESET} Interface is ${GREEN}UP & WORKING${RESET}"
                echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Interface state: $state_raw (normal for GRE tunnels)"
                ;;
            "UP_NO_IP")
                echo -e "${DIM}│${RESET}   ${YELLOW}⚠${RESET} Interface is UP but ${YELLOW}no IP assigned${RESET}"
                echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Interface state: $state_raw"
                ;;
            "DOWN")
                echo -e "${DIM}│${RESET}   ${RED}✗${RESET} Interface exists but is ${RED}DOWN${RESET}"
                echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Interface state: $state_raw"
                ;;
        esac
        echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Current MTU: $mtu_actual"
        
        local ip_info=$(ip addr show dev "$tunnel" 2>/dev/null | grep "inet" | head -1)
        if [[ -n "$ip_info" ]]; then
            local current_ip=$(echo "$ip_info" | awk '{print $2}')
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Current IP: $current_ip"
            if [[ "$current_ip" != "$tunnel_ip" ]]; then
                echo -e "${DIM}│${RESET}   ${YELLOW}⚠${RESET} IP mismatch! Config: $tunnel_ip"
            fi
        else
            echo -e "${DIM}│${RESET}   ${RED}✗${RESET} No IP address assigned"
        fi
        
        if [[ "$version" == "6" ]]; then
            local remote_peer=$(ip -6 tunnel show "$tunnel" 2>/dev/null | grep -o 'remote [0-9a-fA-F:.]*' | awk '{print $2}' | head -1)
        else
            local remote_peer=$(ip tunnel show "$tunnel" 2>/dev/null | grep -o 'remote [0-9.]*' | awk '{print $2}' | head -1)
        fi
        if [[ -n "$remote_peer" ]]; then
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Remote peer: $remote_peer"
            if [[ "$remote_peer" != "$remote_ip" ]]; then
                echo -e "${DIM}│${RESET}   ${YELLOW}⚠${RESET} Remote IP mismatch! Config: $remote_ip"
            fi
        fi
        
        # traffic statistics
        local rx_bytes=$(ip -s link show "$tunnel" 2>/dev/null | grep -A1 "RX:" | tail -1 | awk '{print $1}')
        local tx_bytes=$(ip -s link show "$tunnel" 2>/dev/null | grep -A1 "TX:" | tail -1 | awk '{print $1}')
        if [[ -n "$rx_bytes" && -n "$tx_bytes" ]]; then
            echo -e "${DIM}│${RESET}"
            echo -e "${DIM}│${RESET} ${BOLD}${YELLOW}Traffic Statistics:${RESET}"
            local rx_formatted=$(numfmt --to=iec-i --suffix=B "$rx_bytes" 2>/dev/null || echo "${rx_bytes} bytes")
            local tx_formatted=$(numfmt --to=iec-i --suffix=B "$tx_bytes" 2>/dev/null || echo "${tx_bytes} bytes")
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} RX Bytes: $rx_formatted"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} TX Bytes: $tx_formatted"
            
            if [[ "$rx_bytes" -gt 0 ]] || [[ "$tx_bytes" -gt 0 ]]; then
                echo -e "${DIM}│${RESET}   ${GREEN}✓${RESET} Traffic detected - tunnel appears ${GREEN}operational${RESET}"
            fi
        fi
        
        if [[ "$tunnel_status" == "UP" ]]; then
            local tunnel_ip_only=$(echo "$tunnel_ip" | cut -d'/' -f1)
            if [[ "$version" == "4" ]]; then
                local ip_octets=($(echo "$tunnel_ip_only" | tr '.' ' '))
                if [[ "${ip_octets[3]}" == "1" ]]; then
                    local remote_tunnel_ip="${ip_octets[0]}.${ip_octets[1]}.${ip_octets[2]}.2"
                else
                    local remote_tunnel_ip="${ip_octets[0]}.${ip_octets[1]}.${ip_octets[2]}.1"
                fi
                
                if ping -c 1 -W 2 "$remote_tunnel_ip" >/dev/null 2>&1; then
                    echo -e "${DIM}│${RESET}"
                    echo -e "${DIM}│${RESET} ${BOLD}${YELLOW}Connectivity Test:${RESET}"
                    echo -e "${DIM}│${RESET}   ${GREEN}✓${RESET} Ping successful to remote tunnel IP (${GREEN}$remote_tunnel_ip${RESET})"
                fi
            fi
        fi
    else
        echo -e "${DIM}│${RESET}   ${RED}✗${RESET} Interface ${RED}NOT FOUND${RESET}"
        echo -e "${DIM}│${RESET}   ${YELLOW}⚠${RESET} Tunnel interface does not exist"
    fi
    echo -e "${DIM}│${RESET}"
    
    # systemd service status
    echo -e "${DIM}│${RESET} ${BOLD}${YELLOW}Systemd Service:${RESET}"
    local unit_name="${SERVICE_PREFIX}${tunnel}.service"
    if systemctl list-units --all | grep -q "${unit_name}"; then
        local svc_active=$(systemctl is-active "${unit_name}" 2>/dev/null || echo "inactive")
        local svc_enabled=$(systemctl is-enabled "${unit_name}" 2>/dev/null || echo "disabled")
        
        if [[ "$svc_active" == "active" ]]; then
            echo -e "${DIM}│${RESET}   ${GREEN}✓${RESET} Service is ${GREEN}active${RESET}"
        else
            echo -e "${DIM}│${RESET}   ${RED}✗${RESET} Service is ${RED}inactive${RESET}"
        fi
        
        if [[ "$svc_enabled" == "enabled" ]]; then
            echo -e "${DIM}│${RESET}   ${GREEN}✓${RESET} Service is ${GREEN}enabled${RESET} (auto-start on boot)"
        else
            echo -e "${DIM}│${RESET}   ${YELLOW}⚠${RESET} Service is ${YELLOW}disabled${RESET} (will not start on boot)"
        fi
        
        if [[ "$svc_active" != "active" ]]; then
            local svc_status=$(systemctl status "${unit_name}" --no-pager -n 0 2>/dev/null | tail -1)
            if [[ -n "$svc_status" ]]; then
                echo -e "${DIM}│${RESET}   ${DIM}Status: $svc_status${RESET}"
            fi
        fi
    else
        echo -e "${DIM}│${RESET}   ${RED}✗${RESET} Systemd service ${RED}NOT FOUND${RESET}"
        echo -e "${DIM}│${RESET}   ${YELLOW}⚠${RESET} No systemd service configured for this tunnel"
    fi
    
    echo -e "${DIM}└─────────────────────────────────────────────────────────────┘${RESET}"
}

create_tunnel() {
    banner
    echo -e "${BOLD}${GREEN}🚀 Create a new GRE Tunnel${RESET}"
    echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"
    echo

    show_help
    get_network_interfaces
    show_public_ip_help

    while true; do
        echo -e "${BOLD}${CYAN}1.${RESET} ${YELLOW}Tunnel Name:${RESET}"
        read -p "   Enter tunnel name (e.g., gre1, gre61, tunnel1): " TUNNEL
        if [[ -z "$TUNNEL" ]]; then
            echo -e "${RED}❌ Tunnel name cannot be empty.${RESET}"
            continue
        fi
        if [[ "$TUNNEL" =~ [^a-zA-Z0-9_-] ]]; then
            echo -e "${RED}❌ Invalid tunnel name. Use only letters, numbers, hyphens, and underscores.${RESET}"
            continue
        fi
        # check if tunnel name already exists
        if tunnel_exists "$TUNNEL"; then
            echo -e "${RED}❌ Tunnel name '$TUNNEL' already exists. Please choose a different name.${RESET}"
            continue
        fi
        # check if tunnel interface already exists
        if ip link show "$TUNNEL" >/dev/null 2>&1; then
            echo -e "${RED}❌ A network interface named '$TUNNEL' already exists. Please choose a different name.${RESET}"
            continue
        fi
        break
    done
    echo

    while true; do
        echo -e "${BOLD}${CYAN}2.${RESET} ${YELLOW}IP Version:${RESET}"
        echo -e "   ${DIM}[1]${RESET} IPv4 (recommended)"
        echo -e "   ${DIM}[2]${RESET} IPv6"
        read -p "   Choose [1-2]: " version_choice
        case $version_choice in
            1) VERSION="4"; break ;;
            2) VERSION="6"; break ;;
            *) echo -e "${RED}❌ Invalid choice. Please select 1 or 2.${RESET}" ;;
        esac
    done
    echo

    while true; do
        echo -e "${BOLD}${CYAN}3.${RESET} ${YELLOW}Server Side:${RESET}"
        echo -e "   ${DIM}[1]${RESET} Iran"
        echo -e "   ${DIM}[2]${RESET} External"
        read -p "   Choose [1-2]: " side_choice
        case $side_choice in
            1) SIDE="iran"; break ;;
            2) SIDE="external"; break ;;
            *) echo -e "${RED}❌ Invalid choice. Please select 1 or 2.${RESET}" ;;
        esac
    done
    echo

    while true; do
        echo -e "${BOLD}${CYAN}4.${RESET} ${YELLOW}Local IP (Your server's public IP):${RESET}"
        echo -e "   ${DIM}💡 Use 'curl ifconfig.me' to find your public IP${RESET}"
        read -p "   Enter local IP: " LOCAL_IP
        if validate_ip "$LOCAL_IP" "$VERSION"; then
            break
        else
            if [[ "$VERSION" == "6" ]]; then
                echo -e "${RED}❌ Invalid IP format. Please enter a valid IPv6 address.${RESET}"
            else
                echo -e "${RED}❌ Invalid IP format. Please enter a valid IPv4 address.${RESET}"
            fi
        fi
    done
    echo

    while true; do
        echo -e "${BOLD}${CYAN}5.${RESET} ${YELLOW}Remote IP (Other server's public IP):${RESET}"
        read -p "   Enter remote IP: " REMOTE_IP
        if validate_ip "$REMOTE_IP" "$VERSION"; then
            break
        else
            if [[ "$VERSION" == "6" ]]; then
                echo -e "${RED}❌ Invalid IP format. Please enter a valid IPv6 address.${RESET}"
            else
                echo -e "${RED}❌ Invalid IP format. Please enter a valid IPv4 address.${RESET}"
            fi
        fi
    done
    echo

    echo -e "${BOLD}${CYAN}6.${RESET} ${YELLOW}Tunnel IP Assignment:${RESET}"
    echo -e "   ${DIM}[1]${RESET} Auto-assign (recommended)"
    echo -e "   ${DIM}[2]${RESET} Manual input"
    read -p "   Choose assignment method [1-2]: " ip_choice
    
    case $ip_choice in
        1)
            if [[ "$VERSION" == "4" ]]; then
                # IPv4 GRE tunnel - use /30 subnet
                if [[ "$SIDE" == "iran" ]]; then
                    TUNNEL_IP="10.10.10.1/30"
                    echo -e "   ${GREEN}✓${RESET} Auto-assigned: ${BOLD}${GREEN}$TUNNEL_IP${RESET} (Iran server - IPv4 GRE)"
                else
                    TUNNEL_IP="10.10.10.2/30"
                    echo -e "   ${GREEN}✓${RESET} Auto-assigned: ${BOLD}${GREEN}$TUNNEL_IP${RESET} (External server - IPv4 GRE)"
                fi
            else
                # IPv6 GRE tunnel - use /24 subnet
                if [[ "$SIDE" == "iran" ]]; then
                    TUNNEL_IP="10.10.10.2/24"
                    echo -e "   ${GREEN}✓${RESET} Auto-assigned: ${BOLD}${GREEN}$TUNNEL_IP${RESET} (Iran server - IPv6 GRE)"
                else
                    TUNNEL_IP="10.10.10.1/24"
                    echo -e "   ${GREEN}✓${RESET} Auto-assigned: ${BOLD}${GREEN}$TUNNEL_IP${RESET} (External server - IPv6 GRE)"
                fi
            fi
            echo -e "   ${DIM}💡 This follows the standard GRE tunnel configuration pattern${RESET}"
            ;;
        2)
            # Manual tunnel IP input
            while true; do
                echo -e "   ${YELLOW}Manual Tunnel IP Input:${RESET}"
                if [[ "$VERSION" == "6" ]]; then
                    echo -e "   ${DIM}Examples for IPv6: 2001:db8::1/64, fc00::1/64${RESET}"
                else
                    echo -e "   ${DIM}Examples for IPv4: 10.10.10.1/30, 192.168.1.1/30, 172.16.1.1/24${RESET}"
                fi
                read -p "   Enter tunnel IP with subnet: " TUNNEL_IP
                if validate_cidr "$TUNNEL_IP" "$VERSION"; then
                    echo -e "   ${GREEN}✓${RESET} Manual input: ${BOLD}${GREEN}$TUNNEL_IP${RESET}"
                    break
                else
                    if [[ "$VERSION" == "6" ]]; then
                        echo -e "   ${RED}❌ Invalid IPv6 CIDR format. Please use format like 2001:db8::1/64${RESET}"
                    else
                        echo -e "   ${RED}❌ Invalid IPv4 CIDR format. Please use format like 10.10.10.1/30${RESET}"
                    fi
                fi
            done
            ;;
        *)
            echo -e "   ${RED}❌ Invalid choice. Using auto-assign as default.${RESET}"
            if [[ "$VERSION" == "4" ]]; then
                if [[ "$SIDE" == "iran" ]]; then
                    TUNNEL_IP="10.10.10.1/30"
                else
                    TUNNEL_IP="10.10.10.2/30"
                fi
            else
                if [[ "$SIDE" == "iran" ]]; then
                    TUNNEL_IP="10.10.10.2/24"
                else
                    TUNNEL_IP="10.10.10.1/24"
                fi
            fi
            echo -e "   ${GREEN}✓${RESET} Auto-assigned: ${BOLD}${GREEN}$TUNNEL_IP${RESET}"
            ;;
    esac
    echo

    # MTU with validation
    while true; do
        echo -e "${BOLD}${CYAN}7.${RESET} ${YELLOW}MTU (Maximum Transmission Unit):${RESET}"
        echo -e "   ${DIM}Default: 1470 (recommended for GRE tunnels)${RESET}"
        echo -e "   ${DIM}Valid range: 68-9000 bytes${RESET}"
        read -p "   Enter MTU [1470]: " MTU
        MTU=${MTU:-1470}
        
        # validate MTU
        if validate_mtu "$MTU" "true"; then
            echo
            break
        else
            echo
            echo -e "${RED}Please enter a valid MTU value.${RESET}"
            echo
        fi
    done

    # confirmation
    echo -e "${BOLD}${MAGENTA}📋 Configuration Summary:${RESET}"
    echo -e "${DIM}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${DIM}│${RESET} ${CYAN}Tunnel Name:${RESET} $TUNNEL"
    echo -e "${DIM}│${RESET} ${CYAN}IP Version:${RESET} IPv$VERSION"
    echo -e "${DIM}│${RESET} ${CYAN}Server Side:${RESET} $SIDE"
    echo -e "${DIM}│${RESET} ${CYAN}Local IP:${RESET} $LOCAL_IP"
    echo -e "${DIM}│${RESET} ${CYAN}Remote IP:${RESET} $REMOTE_IP"
    echo -e "${DIM}│${RESET} ${CYAN}Tunnel IP:${RESET} $TUNNEL_IP"
    echo -e "${DIM}│${RESET} ${CYAN}MTU:${RESET} $MTU"
    echo -e "${DIM}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo

    read -p "Create this tunnel? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${BOLD}${BLUE}🔧 Creating tunnel...${RESET}"

    if [[ "$VERSION" == "6" ]]; then
        modprobe ip6_gre
        ip -6 tunnel add $TUNNEL mode ip6gre local $LOCAL_IP remote $REMOTE_IP ttl 255
    else
        modprobe ip_gre
        ip tunnel add $TUNNEL mode gre local $LOCAL_IP remote $REMOTE_IP ttl 255
    fi

	ip addr add $TUNNEL_IP dev $TUNNEL
	ip link set $TUNNEL mtu $MTU
	ip link set $TUNNEL up

	add_tunnel_to_json "$TUNNEL" "$VERSION" "$SIDE" "$LOCAL_IP" "$REMOTE_IP" "$TUNNEL_IP" "$MTU"

	# create and start systemd 
	create_systemd_service "$TUNNEL" "$VERSION" "$SIDE" "$LOCAL_IP" "$REMOTE_IP" "$TUNNEL_IP" "$MTU"

        echo -e "${BOLD}${GREEN}✅ Tunnel $TUNNEL created successfully!${RESET}"
        echo -e "${GREEN}🔗 Tunnel is now active and ready to use.${RESET}"
    else
        echo -e "${YELLOW}❌ Tunnel creation cancelled.${RESET}"
    fi
    echo
}

delete_tunnel() {
    banner
    echo -e "${BOLD}${RED}🗑️  Delete a GRE Tunnel${RESET}"
    echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"
    echo

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${YELLOW}⚠️  No tunnels configured to delete.${RESET}"
        echo
        return
    fi
    
    local tunnel_count=$(jq -r '.tunnels | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
    if [[ "$tunnel_count" == "0" ]]; then
        echo -e "${YELLOW}⚠️  No tunnels configured to delete.${RESET}"
        echo
        return
    fi

    echo -e "${BOLD}${YELLOW}📋 Available Tunnels:${RESET}"
    local count=0
    local tunnels=()
    while IFS= read -r tunnel_json; do
        [[ -z "$tunnel_json" ]] && continue
        ((count++))
        local tunnel=$(echo "$tunnel_json" | jq -r '.tunnel')
        local version=$(echo "$tunnel_json" | jq -r '.version')
        local side=$(echo "$tunnel_json" | jq -r '.side')
        local tunnel_ip=$(echo "$tunnel_json" | jq -r '.tunnel_ip')
        tunnels+=("$tunnel")
        echo -e "   ${DIM}[$count]${RESET} ${CYAN}$tunnel${RESET} (IPv$version, $side, $tunnel_ip)"
    done < <(get_all_tunnels)
    echo

    while true; do
        read -p "Enter tunnel name or number [1-$count]: " selection
        
        if [[ "$selection" =~ ^[0-9]+$ ]]; then
            if [[ $selection -ge 1 && $selection -le $count ]]; then
                TUNNEL="${tunnels[$((selection-1))]}"
                break
            else
                echo -e "${RED}❌ Invalid number. Please enter 1-$count.${RESET}"
            fi
        else
            if [[ " ${tunnels[@]} " =~ " ${selection} " ]]; then
                TUNNEL="$selection"
                break
            else
                echo -e "${RED}❌ Tunnel '$selection' not found.${RESET}"
            fi
        fi
    done

    # confirmation
    echo
    echo -e "${BOLD}${RED}⚠️  WARNING: This will permanently delete tunnel '$TUNNEL'${RESET}"
    read -p "Are you sure you want to delete this tunnel? [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${BOLD}${BLUE}🔧 Deleting tunnel...${RESET}"

	# stop and remove systemd service 
	remove_systemd_service "$TUNNEL"

	ip link set $TUNNEL down 2>/dev/null
	ip tunnel del $TUNNEL 2>/dev/null
	remove_tunnel_from_json "$TUNNEL"

        echo -e "${BOLD}${GREEN}✅ Tunnel $TUNNEL deleted successfully!${RESET}"
    else
        echo -e "${YELLOW}❌ Tunnel deletion cancelled.${RESET}"
    fi
    echo
}

change_tunnel_ip() {
    banner
    echo -e "${BOLD}${CYAN}🔄 Change Tunnel IP${RESET}"
    echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"
    echo

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${YELLOW}⚠️  No tunnels configured to modify.${RESET}"
        echo
        return
    fi
    
    local tunnel_count=$(jq -r '.tunnels | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
    if [[ "$tunnel_count" == "0" ]]; then
        echo -e "${YELLOW}⚠️  No tunnels configured to modify.${RESET}"
        echo
        return
    fi

    echo -e "${BOLD}${YELLOW}📋 Available Tunnels:${RESET}"
    local count=0
    local tunnels=()
    while IFS= read -r tunnel_json; do
        [[ -z "$tunnel_json" ]] && continue
        ((count++))
        local tunnel=$(echo "$tunnel_json" | jq -r '.tunnel')
        local tunnel_ip=$(echo "$tunnel_json" | jq -r '.tunnel_ip')
        tunnels+=("$tunnel")
        echo -e "   ${DIM}[$count]${RESET} ${CYAN}$tunnel${RESET} - Current IP: ${GREEN}$tunnel_ip${RESET}"
    done < <(get_all_tunnels)
    echo

    while true; do
        read -p "Enter tunnel name or number [1-$count]: " selection
        
        if [[ "$selection" =~ ^[0-9]+$ ]]; then
            if [[ $selection -ge 1 && $selection -le $count ]]; then
                TUNNEL="${tunnels[$((selection-1))]}"
                break
            else
                echo -e "${RED}❌ Invalid number. Please enter 1-$count.${RESET}"
            fi
        else
            if [[ " ${tunnels[@]} " =~ " ${selection} " ]]; then
                TUNNEL="$selection"
                break
            else
                echo -e "${RED}❌ Tunnel '$selection' not found.${RESET}"
            fi
        fi
    done

    local tunnel_json=$(get_tunnel_by_name "$TUNNEL")
    if [[ -z "$tunnel_json" ]]; then
        echo -e "${RED}❌ Tunnel not found.${RESET}"
        return
    fi
    
    OLD_IP=$(echo "$tunnel_json" | jq -r '.tunnel_ip')
    echo -e "${BOLD}${BLUE}Current tunnel IP: ${GREEN}$OLD_IP${RESET}"
    echo

    CURRENT_VERSION=$(echo "$tunnel_json" | jq -r '.version')
    CURRENT_SIDE=$(echo "$tunnel_json" | jq -r '.side')
    
    while true; do
        echo -e "${BOLD}${YELLOW}New Tunnel IP:${RESET}"
        echo -e "   ${DIM}Current: $CURRENT_VERSION, $CURRENT_SIDE server${RESET}"
        
        if [[ "$CURRENT_VERSION" == "4" ]]; then
            if [[ "$CURRENT_SIDE" == "iran" ]]; then
                echo -e "   ${GREEN}💡 Suggested for Iran IPv4: 10.10.10.1/30${RESET}"
            else
                echo -e "   ${GREEN}💡 Suggested for External IPv4: 10.10.10.2/30${RESET}"
            fi
        else
            if [[ "$CURRENT_SIDE" == "iran" ]]; then
                echo -e "   ${GREEN}💡 Suggested for Iran IPv6: 10.10.10.2/24${RESET}"
            else
                echo -e "   ${GREEN}💡 Suggested for External IPv6: 10.10.10.1/24${RESET}"
            fi
        fi
        
        read -p "   Enter new tunnel IP: " NEW_IP
        if validate_cidr "$NEW_IP" "$CURRENT_VERSION"; then
            break
        else
            if [[ "$CURRENT_VERSION" == "6" ]]; then
                echo -e "${RED}❌ Invalid IPv6 CIDR format. Please use format like 2001:db8::1/64${RESET}"
            else
                echo -e "${RED}❌ Invalid IPv4 CIDR format. Please use format like 10.10.10.1/30${RESET}"
            fi
        fi
    done
    echo

    # confirmation
    echo -e "${BOLD}${MAGENTA}📋 Change Summary:${RESET}"
    echo -e "${DIM}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${DIM}│${RESET} ${CYAN}Tunnel:${RESET} $TUNNEL"
    echo -e "${DIM}│${RESET} ${CYAN}Old IP:${RESET} $OLD_IP"
    echo -e "${DIM}│${RESET} ${CYAN}New IP:${RESET} $NEW_IP"
    echo -e "${DIM}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo

    read -p "Apply this change? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${BOLD}${BLUE}🔧 Updating tunnel IP...${RESET}"
        
        ip addr del $OLD_IP dev $TUNNEL 2>/dev/null
        ip addr add $NEW_IP dev $TUNNEL

        # update config file
        update_tunnel_ip_in_json "$TUNNEL" "$NEW_IP"
        
        local tunnel_json=$(get_tunnel_by_name "$TUNNEL")
        CURRENT_VERSION=$(echo "$tunnel_json" | jq -r '.version')
        CURRENT_SIDE=$(echo "$tunnel_json" | jq -r '.side')
        CURRENT_LOCAL_IP=$(echo "$tunnel_json" | jq -r '.local_ip')
        CURRENT_REMOTE_IP=$(echo "$tunnel_json" | jq -r '.remote_ip')
        CURRENT_MTU=$(echo "$tunnel_json" | jq -r '.mtu')
        
        # update systemd service with new configuration
        create_systemd_service "$TUNNEL" "$CURRENT_VERSION" "$CURRENT_SIDE" "$CURRENT_LOCAL_IP" "$CURRENT_REMOTE_IP" "$NEW_IP" "$CURRENT_MTU"

        echo -e "${BOLD}${GREEN}✅ Tunnel $TUNNEL IP updated successfully!${RESET}"
        echo -e "${GREEN}🔗 New IP: $NEW_IP${RESET}"
        echo -e "${GREEN}🔧 Systemd service updated and reloaded.${RESET}"
    else
        echo -e "${YELLOW}❌ IP change cancelled.${RESET}"
    fi
    echo
}

menu() {
    while true; do
        banner
        
        local tunnel_count=0
        if [[ -f "$CONFIG_FILE" ]]; then
            tunnel_count=$(jq -r '.tunnels | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
        fi
        
        echo -e "${BOLD}${WHITE}📊 Status: ${GREEN}$tunnel_count tunnels configured${RESET}"
        echo -e "${DIM}─────────────────────────────────────────────────────────────${RESET}"
        echo
        
        echo -e "${BOLD}${YELLOW}📋 Main Menu:${RESET}"
        echo -e "${DIM}┌─────────────────────────────────────────────────────────────┐${RESET}"
        echo -e "${DIM}│${RESET} ${BOLD}${CYAN}[1]${RESET} ${GREEN}🚀 Create New Tunnel${RESET}        ${DIM}Create a new GRE tunnel${RESET}"
        echo -e "${DIM}│${RESET} ${BOLD}${CYAN}[2]${RESET} ${RED}🗑️  Delete Tunnel${RESET}          ${DIM}Remove an existing tunnel${RESET}"
        echo -e "${DIM}│${RESET} ${BOLD}${CYAN}[3]${RESET} ${BLUE}🔄 Change Tunnel IP${RESET}        ${DIM}Modify tunnel IP address${RESET}"
        echo -e "${DIM}│${RESET} ${BOLD}${CYAN}[4]${RESET} ${YELLOW}📋 List Tunnels${RESET}           ${DIM}View all configured tunnels${RESET}"
        echo -e "${DIM}│${RESET} ${BOLD}${CYAN}[5]${RESET} ${CYAN}📊 Tunnel Status${RESET}          ${DIM}Check tunnel status and details${RESET}"
        echo -e "${DIM}│${RESET} ${BOLD}${CYAN}[6]${RESET} ${MAGENTA}❓ Show Help${RESET}              ${DIM}Display help and examples${RESET}"
        echo -e "${DIM}│${RESET} ${BOLD}${CYAN}[0]${RESET} ${WHITE}🚪 Exit${RESET}                  ${DIM}Exit the program${RESET}"
        echo -e "${DIM}└─────────────────────────────────────────────────────────────┘${RESET}"
        echo
        
        read -p "Choose an option [0-6]: " choice

        case $choice in
            1) create_tunnel ;;
            2) delete_tunnel ;;
            3) change_tunnel_ip ;;
            4) list_tunnels ;;
            5) show_tunnel_status ;;
            6) 
                banner
                show_help
                get_network_interfaces
                show_public_ip_help
                echo -e "${BOLD}${GREEN}Press Enter to return to main menu...${RESET}"
                read
                ;;
            0) 
                echo -e "${BOLD}${GREEN}👋 Thank you for using GRE Tunnel Manager!${RESET}"
                echo -e "${DIM}Goodbye!${RESET}"
                exit 0 
                ;;
            *) 
                echo -e "${BOLD}${RED}❌ Invalid choice! Please select 0-6.${RESET}"
                echo
                ;;
        esac

        if [[ "$choice" != "6" ]]; then
            echo -e "${DIM}Press Enter to continue...${RESET}"
            read
        fi
    done
}

if ! check_dependencies; then
    echo -e "${RED}❌ Failed to install required dependencies. Exiting.${RESET}" >&2
    exit 1
fi

init_json_config

menu
