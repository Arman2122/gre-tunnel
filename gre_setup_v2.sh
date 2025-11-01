#!/bin/bash
# GRE Tunnel Manager - IPv4 & IPv6
# Author: Arman2122

CONFIG_FILE="/etc/gre_tunnels.conf"
AUTHOR="Arman2122"

SYSTEMD_DIR="/etc/systemd/system"
SERVICE_PREFIX="gre-"
HELPER_SCRIPT="/usr/local/sbin/gre-tunnel"

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

BG_RED="\e[41m"
BG_GREEN="\e[42m"
BG_YELLOW="\e[43m"
BG_BLUE="\e[44m"

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
	# Remove any existing addr with same prefix then add desired
	current_prefix=$(echo "$tunnel_cidr" | cut -d'/' -f2)
	/sbin/ip addr show dev "$tunnel" | grep -q "$(echo "$tunnel_cidr" | cut -d'/' -f1)" || /sbin/ip addr add "$tunnel_cidr" dev "$tunnel"
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
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_cidr() {
    local cidr=$1
    if [[ $cidr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 0
    else
        return 1
    fi
}

save_config() {
    echo "$1" >> "$CONFIG_FILE"
}

list_tunnels() {
    banner
    echo -e "${BOLD}${YELLOW}📋 Configured Tunnels:${RESET}"
    echo -e "${DIM}┌─────────────────────────────────────────────────────────────┐${RESET}"
    
    if [[ -f "$CONFIG_FILE" && -s "$CONFIG_FILE" ]]; then
        local count=0
        while IFS=',' read -r tunnel version side local_ip remote_ip tunnel_ip mtu; do
            ((count++))
            echo -e "${DIM}│${RESET} ${BOLD}${CYAN}Tunnel #$count:${RESET} $tunnel"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Type: IPv$version GRE"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Side: $side"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Local IP: $local_ip"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Remote IP: $remote_ip"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} Tunnel IP: $tunnel_ip"
            echo -e "${DIM}│${RESET}   ${GREEN}•${RESET} MTU: $mtu"
            echo -e "${DIM}│${RESET}"
        done < "$CONFIG_FILE"
    else
        echo -e "${DIM}│${RESET} ${YELLOW}No tunnels configured yet.${RESET}"
    fi
    
    echo -e "${DIM}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo
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
        if [[ -n "$TUNNEL" && ! "$TUNNEL" =~ [^a-zA-Z0-9_-] ]]; then
            break
        else
            echo -e "${RED}❌ Invalid tunnel name. Use only letters, numbers, hyphens, and underscores.${RESET}"
        fi
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
        if validate_ip "$LOCAL_IP"; then
            break
        else
            echo -e "${RED}❌ Invalid IP format. Please enter a valid IPv4 address.${RESET}"
        fi
    done
    echo

    while true; do
        echo -e "${BOLD}${CYAN}5.${RESET} ${YELLOW}Remote IP (Other server's public IP):${RESET}"
        read -p "   Enter remote IP: " REMOTE_IP
        if validate_ip "$REMOTE_IP"; then
            break
        else
            echo -e "${RED}❌ Invalid IP format. Please enter a valid IPv4 address.${RESET}"
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
                echo -e "   ${DIM}Examples: 10.10.10.1/30, 192.168.1.1/30, 172.16.1.1/24${RESET}"
                read -p "   Enter tunnel IP with subnet: " TUNNEL_IP
                if validate_cidr "$TUNNEL_IP"; then
                    echo -e "   ${GREEN}✓${RESET} Manual input: ${BOLD}${GREEN}$TUNNEL_IP${RESET}"
                    break
                else
                    echo -e "   ${RED}❌ Invalid CIDR format. Please use format like 10.10.10.1/30${RESET}"
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

    echo -e "${BOLD}${CYAN}7.${RESET} ${YELLOW}MTU (Maximum Transmission Unit):${RESET}"
    echo -e "   ${DIM}Default: 1470 (recommended for GRE tunnels)${RESET}"
    read -p "   Enter MTU [1470]: " MTU
    MTU=${MTU:-1470}
    echo

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

	save_config "$TUNNEL,$VERSION,$SIDE,$LOCAL_IP,$REMOTE_IP,$TUNNEL_IP,$MTU"

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

    if [[ ! -f "$CONFIG_FILE" || ! -s "$CONFIG_FILE" ]]; then
        echo -e "${YELLOW}⚠️  No tunnels configured to delete.${RESET}"
        echo
        return
    fi

    echo -e "${BOLD}${YELLOW}📋 Available Tunnels:${RESET}"
    local count=0
    local tunnels=()
    while IFS=',' read -r tunnel version side local_ip remote_ip tunnel_ip mtu; do
        ((count++))
        tunnels+=("$tunnel")
        echo -e "   ${DIM}[$count]${RESET} ${CYAN}$tunnel${RESET} (IPv$version, $side, $tunnel_ip)"
    done < "$CONFIG_FILE"
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
	sed -i "/^$TUNNEL,/d" "$CONFIG_FILE"

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

    if [[ ! -f "$CONFIG_FILE" || ! -s "$CONFIG_FILE" ]]; then
        echo -e "${YELLOW}⚠️  No tunnels configured to modify.${RESET}"
        echo
        return
    fi

    echo -e "${BOLD}${YELLOW}📋 Available Tunnels:${RESET}"
    local count=0
    local tunnels=()
    while IFS=',' read -r tunnel version side local_ip remote_ip tunnel_ip mtu; do
        ((count++))
        tunnels+=("$tunnel")
        echo -e "   ${DIM}[$count]${RESET} ${CYAN}$tunnel${RESET} - Current IP: ${GREEN}$tunnel_ip${RESET}"
    done < "$CONFIG_FILE"
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

    OLD_IP=$(grep "^$TUNNEL," "$CONFIG_FILE" | cut -d',' -f6)
    echo -e "${BOLD}${BLUE}Current tunnel IP: ${GREEN}$OLD_IP${RESET}"
    echo

    TUNNEL_INFO=$(grep "^$TUNNEL," "$CONFIG_FILE")
    CURRENT_VERSION=$(echo "$TUNNEL_INFO" | cut -d',' -f2)
    CURRENT_SIDE=$(echo "$TUNNEL_INFO" | cut -d',' -f3)
    
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
        if validate_cidr "$NEW_IP"; then
            break
        else
            echo -e "${RED}❌ Invalid CIDR format. Please use format like 10.10.10.1/30${RESET}"
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

    sed -i "s#$OLD_IP#$NEW_IP#g" "$CONFIG_FILE"

        echo -e "${BOLD}${GREEN}✅ Tunnel $TUNNEL IP updated successfully!${RESET}"
        echo -e "${GREEN}🔗 New IP: $NEW_IP${RESET}"
    else
        echo -e "${YELLOW}❌ IP change cancelled.${RESET}"
    fi
    echo
}

menu() {
    while true; do
        banner
        
        local tunnel_count=0
        if [[ -f "$CONFIG_FILE" && -s "$CONFIG_FILE" ]]; then
            tunnel_count=$(wc -l < "$CONFIG_FILE")
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
        echo -e "${DIM}│${RESET} ${BOLD}${CYAN}[5]${RESET} ${MAGENTA}❓ Show Help${RESET}              ${DIM}Display help and examples${RESET}"
        echo -e "${DIM}│${RESET} ${BOLD}${CYAN}[0]${RESET} ${WHITE}🚪 Exit${RESET}                  ${DIM}Exit the program${RESET}"
        echo -e "${DIM}└─────────────────────────────────────────────────────────────┘${RESET}"
        echo
        
        read -p "Choose an option [0-5]: " choice

        case $choice in
            1) create_tunnel ;;
            2) delete_tunnel ;;
            3) change_tunnel_ip ;;
            4) list_tunnels ;;
            5) 
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
                echo -e "${BOLD}${RED}❌ Invalid choice! Please select 0-5.${RESET}"
                echo
                ;;
        esac

        if [[ "$choice" != "5" ]]; then
            echo -e "${DIM}Press Enter to continue...${RESET}"
            read
        fi
    done
}

# main menu
menu
