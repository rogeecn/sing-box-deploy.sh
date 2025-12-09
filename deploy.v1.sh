#!/bin/bash

#================================================================================
#
#          FILE: deploy.sh
#
#         USAGE: sudo ./deploy.sh
#
#   DESCRIPTION: A one-click deployment script for sing-box and Hysteria2.
#                Automates the installation and configuration process.
#
#       OPTIONS: ---
#  REQUIREMENTS: root privileges, curl, socat, jq
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Gemini
#       CREATED: 2025-12-03
#      REVISION: 1.0
#
#================================================================================

# --- Colors and Formatting ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'

info() {
    echo -e "${C_BLUE}[INFO] ${*}${C_RESET}"
}

success() {
    echo -e "${C_GREEN}[SUCCESS] ${*}${C_RESET}"
}

warn() {
    echo -e "${C_YELLOW}[WARNING] ${*}${C_RESET}"
}

error() {
    echo -e "${C_RED}[ERROR] ${*}${C_RESET}"
    exit 1
}

# --- Pre-flight Checks ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Please use 'sudo'."
    fi
}

check_dependencies() {
    info "Checking for required dependencies..."
    local missing_deps=()
    local deps=("curl" "socat" "jq")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        warn "Missing dependencies: ${missing_deps[*]}. Attempting to install them."
        if command -v apt-get &>/dev/null; then
            apt-get update && apt-get install -y "${missing_deps[@]}"
        elif command -v yum &>/dev/null; then
            yum install -y "${missing_deps[@]}"
        elif command -v dnf &>/dev/null; then
            dnf install -y "${missing_deps[@]}"
        else
            error "Could not install dependencies. Please install them manually and re-run the script."
        fi
    fi
    success "All dependencies are satisfied."
}

# --- Global Variables ---
PUBLIC_IP=$(curl -4 -s ip.sb || curl -4 -s ifconfig.me || curl -4 -s api.ipify.org)
DOMAIN=""

# --- Certificate Management ---
install_acme() {
    info "Installing acme.sh..."
    if [ ! -d "$HOME/.acme.sh" ]; then
        curl https://get.acme.sh | sh
        if [ $? -ne 0 ]; then
            error "Failed to install acme.sh."
        fi
    else
        info "acme.sh is already installed."
    fi
    # shellcheck source=/root/.bashrc
    source "$HOME/.bashrc"
}

issue_certificate() {
    read -rp "Please enter your domain name: " DOMAIN
    if [ -z "$DOMAIN" ]; then
        error "Domain name cannot be empty."
    fi
    info "Domain set to: $DOMAIN"
    
    local cert_dir="/etc/ssl/private/$DOMAIN"
    if [ -f "$cert_dir/fullchain.cer" ]; then
        warn "Certificate for $DOMAIN already exists. Skipping issuance."
        return
    fi
    
    install_acme
    
    # Register account to avoid errors with some CAs
    info "Registering acme.sh account..."
    "$HOME/.acme.sh/acme.sh" --register-account -m "admin@${DOMAIN}" --server letsencrypt &>/dev/null
    
    info "Attempting to issue certificate for $DOMAIN using standalone mode (requires port 80)..."
    warn "Please ensure your domain points to this server's IP ($PUBLIC_IP) and port 80 is not blocked."
    
    if "$HOME/.acme.sh/acme.sh" --issue --standalone -d "$DOMAIN" --keylength ec-256 --server letsencrypt; then
        mkdir -p "$cert_dir"
        if "$HOME/.acme.sh/acme.sh" --install-cert -d "$DOMAIN" \
            --fullchain-file "$cert_dir/fullchain.cer" \
            --key-file "$cert_dir/private.key" \
            --ecc; then
            success "Certificate issued and installed successfully to $cert_dir."
            CERT_IS_SELF_SIGNED=false
        else
            error "Failed to install certificate."
        fi
    else
        warn "Standard certificate issuance failed."
        warn "This typically happens if your domain is proxied by Cloudflare (Orange Cloud enabled)."
        warn "Hysteria2 requires a DIRECT connection (Grey Cloud / DNS Only)."
        warn "Generating a SELF-SIGNED certificate as a fallback so installation can finish..."
        warn "IMPORTANT: You likely need to disable Cloudflare Proxy for this to work, and clients must allow insecure connections."
        
        mkdir -p "$cert_dir"
        openssl req -x509 -newkey rsa:2048 -keyout "$cert_dir/private.key" -out "$cert_dir/fullchain.cer" -days 3650 -nodes -subj "/CN=$DOMAIN" >/dev/null 2>&1
        
        success "Self-signed certificate generated at $cert_dir."
        CERT_IS_SELF_SIGNED=true
    fi
}

# --- Installation Functions ---
install_singbox() {
    info "Installing sing-box..."
    if command -v sing-box &>/dev/null; then
        info "sing-box is already installed."
        return
    fi
    
    local LATEST_URL
    LATEST_URL=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.assets[] | select(.name | test("linux-amd64.tar.gz$")) | .browser_download_url')
    
    if [ -z "$LATEST_URL" ]; then
        error "Failed to get the latest sing-box release URL."
    fi
    
    wget -qO sing-box.tar.gz "$LATEST_URL"
    tar -xzf sing-box.tar.gz
    mv sing-box-*/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    rm -rf sing-box.tar.gz sing-box-*
    
    success "sing-box installed successfully."
}

install_hysteria() {
    info "Installing Hysteria2..."
    if command -v hysteria &>/dev/null; then
        info "Hysteria2 is already installed."
        return
    fi
    
    local LATEST_URL
    LATEST_URL=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r '.assets[] | select(.name | test("linux-amd64$")) | .browser_download_url')

    if [ -z "$LATEST_URL" ]; then
        error "Failed to get the latest Hysteria2 release URL."
    fi
    
    wget -qO hysteria "$LATEST_URL"
    mv hysteria /usr/local/bin/hysteria
    chmod +x /usr/local/bin/hysteria
    
    success "Hysteria2 installed successfully."
}

# --- Configuration & Service Setup ---

setup_systemd_service() {
    local service_name="$1"
    local config_path="$2"
    local exec_start="$3"
    
    cat > "/etc/systemd/system/${service_name}.service" <<EOF
[Unit]

Description=${service_name} service
After=network.target


[Service]

ExecStart=${exec_start}
Restart=on-failure
RestartSec=10
LimitNPROC=10000
LimitNOFILE=1000000


[Install]

WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "${service_name}"
    systemctl restart "${service_name}"
    
    # Wait a moment for service to start
    sleep 2
    
    if systemctl is-active --quiet "${service_name}"; then
        success "${service_name} is running."
    else
        error "${service_name} failed to start. Check logs with 'journalctl -u ${service_name}'."
    fi
}

configure_vless_reality() {
    install_singbox
    info "Configuring VLESS + XTLS Reality..."
    
    local VLESS_UUID
    VLESS_UUID=$(sing-box generate uuid)
    local KEY_PAIR
    KEY_PAIR=$(sing-box generate reality-keypair)
    local PRIVATE_KEY
    PRIVATE_KEY=$(echo "$KEY_PAIR" | awk '/PrivateKey/ {print $2}')
    local PUBLIC_KEY
    PUBLIC_KEY=$(echo "$KEY_PAIR" | awk '/PublicKey/ {print $2}')
    local SHORT_ID
    SHORT_ID=$(openssl rand -hex 8)
    
    mkdir -p /etc/sing-box
    cat > /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "uuid": "${VLESS_UUID}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.apple.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.apple.com",
            "server_port": 443
          },
          "private_key": "${PRIVATE_KEY}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    }
  ]
}
EOF
    
    setup_systemd_service "sing-box" "/etc/sing-box/config.json" "/usr/local/bin/sing-box run -c /etc/sing-box/config.json"
    
    # URL encode the public key for safety
    local SAFE_PUBLIC_KEY
    SAFE_PUBLIC_KEY=$(echo -n "$PUBLIC_KEY" | jq -sRr @uri)

    local share_link="vless://${VLESS_UUID}@${PUBLIC_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.apple.com&fp=chrome&pbk=${SAFE_PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#VLESS-REALITY"
    
    success "VLESS + XTLS Reality installation complete!"
    echo -e "\n${C_CYAN}--- Configuration Details ---${C_RESET}"
    echo -e "  ${C_YELLOW}Address:${C_RESET}      ${PUBLIC_IP}"
    echo -e "  ${C_YELLOW}Port:${C_RESET}         443"
    echo -e "  ${C_YELLOW}UUID:${C_RESET}         ${VLESS_UUID}"
    echo -e "  ${C_YELLOW}Flow:${C_RESET}         xtls-rprx-vision"
    echo -e "  ${C_YELLOW}Security:${C_RESET}     reality"
    echo -e "  ${C_YELLOW}SNI:${C_RESET}          www.apple.com"
    echo -e "  ${C_YELLOW}Public Key:${C_RESET}   ${PUBLIC_KEY}"
    echo -e "  ${C_YELLOW}Short ID:${C_RESET}     ${SHORT_ID}"
    echo -e "\n${C_CYAN}--- Share Link ---${C_RESET}"
    echo -e "${C_GREEN}${share_link}${C_RESET}\n"
}

configure_vless_ws() {
    info "Configuring VLESS + WebSocket + TLS..."
    
    read -rp "Please enter your domain name: " DOMAIN
    if [ -z "$DOMAIN" ]; then
        error "Domain name cannot be empty."
    fi
    info "Domain set to: $DOMAIN"

    install_singbox
    
    local VLESS_UUID
    VLESS_UUID=$(sing-box generate uuid)
    local WS_PATH
    WS_PATH="/$(openssl rand -hex 8)"
    
    # Generate Self-Signed Certificate for Cloudflare
    mkdir -p /etc/sing-box
    local CERT_FILE="/etc/sing-box/self_signed.crt"
    local KEY_FILE="/etc/sing-box/self_signed.key"
    
    info "Generating self-signed certificate for $DOMAIN..."
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 3650 -nodes -subj "/CN=$DOMAIN" >/dev/null 2>&1
    
    cat > /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-ws-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "uuid": "${VLESS_UUID}"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "${WS_PATH}"
      },
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN}",
        "certificate_path": "${CERT_FILE}",
        "key_path": "${KEY_FILE}"
      }
    }
  ]
}
EOF

    setup_systemd_service "sing-box" "/etc/sing-box/config.json" "/usr/local/bin/sing-box run -c /etc/sing-box/config.json"
    
    local share_link="vless://${VLESS_UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=${WS_PATH}#VLESS-WS"

    success "VLESS + WS + TLS installation complete!"
    warn "Remember to point your domain ($DOMAIN) to $PUBLIC_IP in Cloudflare and enable the orange cloud (proxy)!"
    warn "Ensure Cloudflare's SSL/TLS encryption mode is set to 'Full' (not 'Full Strict') for this configuration."
    echo -e "\n${C_CYAN}--- Configuration Details ---${C_RESET}"
    echo -e "  ${C_YELLOW}Address:${C_RESET}      ${DOMAIN}"
    echo -e "  ${C_YELLOW}Port:${C_RESET}         443"
    echo -e "  ${C_YELLOW}UUID:${C_RESET}         ${VLESS_UUID}"
    echo -e "  ${C_YELLOW}Transport:${C_RESET}    websocket"
    echo -e "  ${C_YELLOW}Security:${C_RESET}     tls"
    echo -e "  ${C_YELLOW}SNI:${C_RESET}          ${DOMAIN}"
    echo -e "  ${C_YELLOW}Path:${C_RESET}         ${WS_PATH}"
    echo -e "\n${C_CYAN}--- Share Link ---${C_RESET}"
    echo -e "${C_GREEN}${share_link}${C_RESET}\n"
}

configure_hysteria2() {

    issue_certificate

    install_hysteria

    info "Configuring Hysteria2..."

    

    local HY_PASSWORD

    HY_PASSWORD=$(openssl rand -hex 16)

    # Use a single random port instead of a range to avoid bind errors

    local HY_PORT

    HY_PORT=$(shuf -i 10000-60000 -n 1)

    

    mkdir -p /etc/hysteria

    cat > /etc/hysteria/config.yaml <<EOF

listen: :${HY_PORT}



tls:

  cert: /etc/ssl/private/${DOMAIN}/fullchain.cer

  key: /etc/ssl/private/${DOMAIN}/private.key



auth:

  type: password

  password: ${HY_PASSWORD}



masquerade:

  type: proxy

  proxy:

    url: https://www.bing.com

    rewriteHost: true

EOF

    

    setup_systemd_service "hysteria" "/etc/hysteria/config.yaml" "/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml"

    

    local share_link="hysteria2://${HY_PASSWORD}@${DOMAIN}:${HY_PORT}?sni=${DOMAIN}#Hysteria2"

    

    if [ "$CERT_IS_SELF_SIGNED" = true ]; then

        share_link="${share_link}&insecure=1"

    fi

    

    success "Hysteria2 installation complete!"

    warn "IMPORTANT: Please open UDP port ${HY_PORT} in your server's firewall!"

    if [ "$CERT_IS_SELF_SIGNED" = true ]; then

        warn "Self-signed certificate used. Please ensure your client enables 'Allow Insecure' (insecure=1)."

    fi

    echo -e "\n${C_CYAN}--- Configuration Details ---${C_RESET}"

    echo -e "  ${C_YELLOW}Address:${C_RESET}      ${DOMAIN}"

    echo -e "  ${C_YELLOW}Port (UDP):${C_RESET}  ${HY_PORT}"

    echo -e "  ${C_YELLOW}Password:${C_RESET}     ${HY_PASSWORD}"

    echo -e "  ${C_YELLOW}SNI:${C_RESET}          ${DOMAIN}"

    echo -e "\n${C_CYAN}--- Share Link ---${C_RESET}"

    echo -e "${C_GREEN}${share_link}${C_RESET}\n"

}

# --- Uninstall ---
uninstall() {
    warn "This will stop and remove sing-box, Hysteria2, and related configurations."
    read -rp "Are you sure you want to uninstall? [y/N]: " confirm
    if [[ ! $confirm =~ ^[yY](es)?$ ]]; then
        info "Uninstallation cancelled."
        return
    fi

    systemctl stop sing-box hysteria &>/dev/null
    systemctl disable sing-box hysteria &>/dev/null

    rm -f /etc/systemd/system/sing-box.service
    rm -f /etc/systemd/system/hysteria.service
    systemctl daemon-reload

    rm -rf /etc/sing-box
    rm -rf /etc/hysteria

    rm -f /usr/local/bin/sing-box
    rm -f /usr/local/bin/hysteria

    # We don't remove acme.sh or certificates by default
    warn "acme.sh and issued certificates were not removed to avoid data loss."

    success "All proxy services and configurations have been uninstalled."
}

# --- Main Menu ---
main_menu() {
    clear
    echo -e "${C_CYAN}=======================================================${C_RESET}"
    echo -e "${C_GREEN}      One-Click Proxy Deployment Script by Gemini      ${C_RESET}"
    echo -e "${C_CYAN}=======================================================${C_RESET}"
    echo -e "  Your Server IP: ${C_YELLOW}${PUBLIC_IP}${C_RESET}"
    echo ""
    echo -e "  Please choose an installation option:"
    echo -e "  ${C_GREEN}1.${C_RESET} Install ${C_YELLOW}VLESS + XTLS Reality${C_RESET} (Recommended for direct connection)"
    echo -e "  ${C_GREEN}2.${C_RESET} Install ${C_YELLOW}VLESS + WebSocket + TLS${C_RESET} (For Cloudflare CDN)"
    echo -e "  ${C_GREEN}3.${C_RESET} Install ${C_YELLOW}Hysteria2${C_RESET} (For unstable networks)"
    echo -e "  ----------------------------------------------------"
    echo -e "  ${C_RED}4.${C_RESET} ${C_YELLOW}Uninstall All Services${C_RESET}"
    echo -e "  ${C_RED}0.${C_RESET} ${C_YELLOW}Exit${C_RESET}"
    echo ""
    read -rp "Enter your choice [0-4]: " choice

    case $choice in
        1)
            configure_vless_reality
            ;; 
        2)
            configure_vless_ws
            ;; 
        3)
            configure_hysteria2
            ;; 
        4)
            uninstall
            ;; 
        0)
            info "Exiting script. Goodbye!"
            exit 0
            ;; 
        *)
            error "Invalid option. Please try again."
            ;; 
    esac
}

# --- Script Entrypoint ---
check_root
check_dependencies
main_menu