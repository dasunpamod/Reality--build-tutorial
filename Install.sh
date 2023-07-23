#!/bin/bash

# define color variables
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# install dependencies
function check_dependencies() {
    local packages=("wget" "jq" "openssl")
    
    if [[ -n $(command -v apt-get) ]]; then
        packages+=("uuid-runtime")
    elif [[ -n $(command -v yum) ]]; then
        packages+=("util-linux")
    else
        echo -e "${RED} cannot determine the system package manager, please install dependencies manually. ${NC}"
        exit 1
    fi

    for package in "${packages[@]}"; do
        if ! command -v "$package" &> /dev/null; then
            echo "Install dependencies: $package"
            if [[ -n $(command -v apt-get) ]]; then
                apt-get -y install "$package"
            elif [[ -n $(command -v yum) ]]; then
                yum -y install "$package"
            fi
        fi
    done
}

# enable BBR
function enable_bbr() {
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "Enable BBR..."
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo "BBR is enabled"
    else
        echo -e "${YELLOW}BBR is enabled, skip configuration. ${NC}"
    fi
}

# Download and install the latest Sing-Box version
function install_latest_sing_box() {
    local arch=$(uname -m)
    local url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url

    # Determine the appropriate download URL according to the VPS architecture
    case $arch in
        x86_64)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-amd64.tar.gz")
            ;;
        armv7l)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-armv7.tar.gz")
            ;;
        aarch64)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-arm64.tar.gz")
            ;;
        amd64v3)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-amd64v3.tar.gz")
            ;;
        *)
            echo -e "Unsupported architecture for ${RED}: $arch${NC}"
            return 1
            ;;
    esac

    # Download and install Sing-Box
    if [ -n "$download_url" ]; then
        echo "Downloading Sing-Box..."
        curl -L -o sing-box.tar.gz "$download_url"
        tar -xzf sing-box.tar.gz -C /usr/local/bin --strip-components=1
        rm sing-box.tar.gz

        # Grant executable permissions
        chmod +x /usr/local/bin/sing-box

        echo "Sing-Box installed successfully!"
    else
        echo -e "${RED} cannot get the download URL of Sing-Box. ${NC}"
        return 1
    fi
}

# Check firewall configuration
function check_firewall_configuration() {
    local listen_port=$(jq -r '.inbounds[0].listen_port' /usr/local/etc/sing-box/config.json)
    local os_name=$(uname -s)
    local firewall

    if [[ $os_name == "Linux" ]]; then
        if command -v ufw >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1; then
            firewall="ufw"
        elif command -v iptables >/dev/null 2>&1 && command -v firewalld >/dev/null 2>&1; then
            firewall="iptables-firewalld"
        fi
    fi

    if [[ -z $firewall ]]; then
        echo -e "${RED} cannot detect the applicable firewall configuration tool, please configure the firewall manually. ${NC}"
        return
    fi

    echo "Check firewall configuration..."

    case $firewall in
        ugh)
            if ! ufw status | grep -q "Status: active"; then
                ufw enable
            fi

            if ! ufw status | grep -q "$listen_port"; then
                ufw allow "$listen_port"
            fi

            echo "The firewall configuration has been updated."
            ;;
        iptables-firewalld)
            if command -v iptables >/dev/null 2>&1; then
                if ! iptables -C INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
                    iptables -A INPUT -p tcp --dport "$listen_port" -j ACCEPT
                fi

                iptables-save > /etc/sysconfig/iptables

                echo "The iptables firewall configuration has been updated."
            fi

            if command -v firewalld >/dev/null 2>&1; then
                if ! firewall-cmd --state | grep -q "running"; then
                    systemctl start firewalld
                    systemctl enable firewalld
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/tcp"; then
                    firewall-cmd --zone=public --add-port="$listen_port/tcp" --permanent
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/udp"; then
                    firewall-cmd --zone=public --add-port="$listen_port/udp" --permanent
                fi

                firewall-cmd --reload

                echo "firewalld firewall configuration has been updated."
            fi
            ;;
    esac
}

# Configure sing-box boot self-start service
function configure_sing_box_service() {
    echo "Configure sing-box boot self-starting service..."
    echo "[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
Restart=on-failure
RestartSec=1800s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target" |  tee /etc/systemd/system/sing-box.service >/dev/null
}

# Check if the sing-box folder exists, create it if not
function check_sing_box_folder() {
    local folder="/usr/local/etc/sing-box"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
    fi
}

# generate random UUID
function generate_uuid() {
    local uuid=$(uuidgen)
    echo "$uuid"
}

# Generate a random ShortId
function generate_short_id() {
    local length=$1
    local short_id=$(openssl rand -hex "$length")
    echo "$short_id"
}

# Select flow control type
function select_flow_type() {
    local flow_type="xtls-rprx-vision"

    while true; do
        read -p "Please select the flow control type:
 [1]. xtls-rprx-vision（vless+vision+reality)
 [2]. Leave blank (vless+h2/grpc+reality)
Please enter the option (default is xtls-rprx-vision): " flow_option

        case $flow_option in
            "" | 1)
                flow_type="xtls-rprx-vision"
                break
                ;;
            2)
                flow_type=""
                break
                ;;
            *)
                echo -e "${RED} wrong option, please re-enter! ${NC}" >&2
                ;;
        esac
    done

    echo "$flow_type"
}

# Listening port configuration
function generate_listen_port_config() {
    local listen_port

    while true; do
        read -p "Please enter the listening port (default is 443): " listen_port
        listen_port=${listen_port:-443}

        if ! [[ "$listen_port" =~ ^[1-9][0-9]{0,4}$ || "$listen_port" == "443" ]]; then
            echo -e "${RED} error: port range 1-65535, please re-enter! ${NC}" >&2
        else
            break
        fi
    done

    echo "$listen_port"
}

# Verify that the server supports TLS 1.3
function validate_tls13_support() {
    local server="$1"
    local tls13_supported="false"

    if command -v openssl >/dev/null 2>&1; then
        local openssl_output=$(timeout 90s openssl s_client -connect "$server:443" -tls1_3 2>&1)
        if [[ $openssl_output == *"Protocol  : TLSv1.3"* ]]; then
            tls13_supported="true"
        fi
    fi

    echo "$tls13_supported"
}

# ServerName configuration
function generate_server_name_config() {
    local server_name="www.gov.hk"

    read -p "Please enter a list of available serverNames (default is www.gov.hk): " user_input
    
    # Verify that the server supports TLS 1.3
    echo "Verifying TLS versions supported by server..." >&2
    
    if [[ -n "$user_input" ]]; then
        server_name="$user_input"
        local tls13_support=$(validate_tls13_support "$server_name")

        if [[ "$tls13_support" == "false" ]]; then
            echo -e "${RED}The URL does not support TLS 1.3, please re-enter! ${NC}" >&2
            generate_server_name_config
            return
        fi
    fi

    echo "$server_name"
}

# Target site configuration
function generate_target_server_config() {
    local target_server="www.gov.hk"

    read -p "Please enter the target website address (default is www.gov.hk): " user_input
    
    # Verify that the target server supports TLS 1.3
    echo "Verifying TLS versions supported by server..." >&2
    
    if [[ -n "$user_input" ]]; then
        target_server="$user_input"
        local tls13_support=$(validate_tls13_support "$target_server")

        if [[ "$tls13_support" == "false" ]]; then
            echo -e "${RED}The target website address does not support TLS 1.3, please re-enter! ${NC}" >&2
            generate_target_server_config
            return
        fi
    fi

    echo "$target_server"
}

# Private key configuration
function generate_private_key_config() {
    local private_key

    while true; do
        read -p "Please enter the private key (the private key is randomly generated by default): " private_key

        if [[ -z "$private_key" ]]; then
            local keypair_output=$(sing-box generate reality-keypair)
            private_key=$(echo "$keypair_output" | awk -F: '/PrivateKey/{gsub(/ /, "", $2); print $2}')
            echo "$keypair_output" | awk -F: '/PublicKey/{gsub(/ /, "", $2); print $2}' > /tmp/public_key_temp.txt
            break
        fi

        # Verify that the private key format is correct
        if openssl pkey -inform PEM -noout -text -in <(echo "$private_key") >/dev/null 2>&1; then
            break
        else
            echo -e "${RED} invalid private key, please re-enter! ${NC}" >&2
        fi
    done
    
    echo "$private_key"
}

# ShortIds configuration
function generate_short_ids_config() {
    local short_ids=()
    local add_more_short_ids="y"
    local length=8

    while [[ "$add_more_short_ids" == "y" ]]; do
        if [[ ${#short_ids[@]} -eq 8 ]]; then
            echo -e "${YELLOW} has reached the maximum number of shortIds! ${NC}" >&2
            break
        fi

        local short_id=$(generate_short_id "$length")
        short_ids+=("$short_id")

        while true; do
            read -p "Do you want to continue adding shortIds? (y/n, default is n): " add_more_short_ids
            add_more_short_ids=${add_more_short_ids:-n}
            case $add_more_short_ids in
                [yY])
                    add_more_short_ids="y"
                    break
                    ;;
                [nN])
                    add_more_short_ids="n"
                    break
                    ;;
                *)
                    echo -e "${RED} wrong option, please re-enter! ${NC}" >&2
                    ;;
            esac
        done

        if [[ "$add_more_short_ids" == "y" ]]; then
            length=$((length - 1))
        fi
    done

    local short_ids_config=$(printf '          "%s",\n' "${short_ids[@]}")
    short_ids_config=${short_ids_config%,}  

    echo "$short_ids_config"
}

# flow control configuration
function generate_flow_config() {
    local flow_type="$1"
    local transport_config=""

    if [[ "$flow_type" != "" ]]; then
        return  
    fi

    local transport_type=""

    while true; do
        read -p "Please select the transport layer protocol:
 [1]. http
 [2]. grpc
Please enter an option (default is http): " transport_option

        case $transport_option in
            1)
                transport_type="http"
                break
                ;;
            2)
                transport_type="grpc"
                break
                ;;
            "")
                transport_type="http"
                break
                ;;                
            *)
                echo -e "${RED} wrong option, please re-enter! ${NC}" >&2
                ;;
        esac
    done

    transport_config='
      "transport": {
        "type": "'"$transport_type"'"
      },'

    echo "$transport_config"
}

# user configuration
function generate_user_config() {
    local flow_type="$1"
    local users=()
    local add_more_users="y"

    while [[ "$add_more_users" == "y" ]]; do
        local user_uuid

        while true; do
            read -p "Please enter the user UUID (UUID is randomly generated by default): " user_uuid

            if [[ -z "$user_uuid" ]]; then
                user_uuid=$(generate_uuid)
                break
            fi

            if [[ $user_uuid =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; then
                break
            else
                echo -e "${RED} invalid UUID, please re-enter! ${NC}" >&2
            fi
        done

        users+=('
        {
          "uuid": "'"$user_uuid"'",
          "flow": "'"$flow_type"'"
        },')

        while true; do
            read -p "Continue to add users? (y/n, default is n): " add_more_users
            add_more_users=${add_more_users:-n}
            case $add_more_users in
                [yY])
                    add_more_users="y"
                    break
                    ;;
                [nN])
                    add_more_users="n"
                    break
                    ;;
                *)
                    echo -e "${RED} wrong option, please re-enter! ${NC}" >&2
                    ;;
            esac
        done
    done

    # Remove the comma at the end of the last user configuration
    users[-1]=${users[-1]%,}

    echo "${users[*]}"
}

# Generate Sing-Box configuration file
function generate_sing_box_config() {
    check_sing_box_folder
    local config_file="/usr/local/etc/sing-box/config.json"

    local listen_port=$(generate_listen_port_config)
    local flow_type=$(select_flow_type)

    transport_config=$(generate_flow_config "$flow_type")

    users=$(generate_user_config "$flow_type")

    local server_name=$(generate_server_name_config)
    local target_server=$(generate_target_server_config)
    local private_key=$(generate_private_key_config)
    local short_ids=$(generate_short_ids_config)

    # Generate Sing-Box configuration file
    local config_content='{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": '$listen_port',
      "users": ['"$users"'
      ],'"$transport_config"'
      "tls": {
        "enabled": true,
        "server_name": "'"$server_name"'",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "'"$target_server"'",
            "server_port": 443
          },
          "private_key": "'"$private_key"'",
          "short_id": [
'"$short_ids"'
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}'

    echo "$config_content" > "$config_file"

    echo "Sing-Box configuration file has been generated and saved to $config_file"       
}

# Extract configuration file information
function extract_config_info_and_public_key() {
    local config_file="/usr/local/etc/sing-box/config.json"

        local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
        local users=$(jq -r '.inbounds[0].users[].uuid' "$config_file")
        local flow_type=$(jq -r '.inbounds[0].users[].flow' "$config_file")
        local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
        local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
        local target_server=$(jq -r '.inbounds[0].tls.reality.handshake.server' "$config_file")
        local short_ids=$(jq -r '.inbounds[0].tls.reality.short_id[]' "$config_file")
        local public_key=$(cat /tmp/public_key_temp.txt)

        echo -e "${GREEN} node configuration information: ${NC}"
        echo -e "${CYAN}==================================================================${NC}"  
        echo -e "${GREEN} listening port: $listen_port${NC}"
        echo -e "${CYAN}------------------------------------------------------------------${NC}" 
        echo -e "${GREEN}User UUID:${NC}"
        echo -e "${GREEN}$users${NC}"
        echo -e "${CYAN}------------------------------------------------------------------${NC}"
        echo -e "${GREEN} flow control type: $flow_type${NC}"
        echo -e "${CYAN}------------------------------------------------------------------${NC}"
        echo -e "${GREEN} transport layer protocol: $transport_type${NC}"
        echo -e "${CYAN}------------------------------------------------------------------${NC}"
        echo -e "${GREEN}ServerName: $server_name${NC}"
        echo -e "${CYAN}------------------------------------------------------------------${NC}"
        echo -e "${GREEN} target website address: $target_server${NC}"
        echo -e "${CYAN}------------------------------------------------------------------${NC}"
        echo -e "${GREEN}Short ID:${NC}"
        echo -e "${GREEN}$short_ids${NC}"
        echo -e "${CYAN}------------------------------------------------------------------${NC}"
        echo -e "${GREEN}PublicKey: $public_key${NC}"
        echo -e "${CYAN}==================================================================${NC}"
}

# Start the sing-box service
function start_sing_box_service() {
    echo "Starting sing-box service..."
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box

    if [[ $? -eq 0 ]]; then
        echo "sing-box service started."
    else
        echo -e "${RED} failed to start the sing-box service. ${NC}"
    fi    
}

# install sing-box
function install_sing_box() {
    check_dependencies
    enable_bbr
    install_latest_sing_box
    configure_sing_box_service
    generate_sing_box_config
    check_firewall_configuration
    start_sing_box_service
    extract_config_info_and_public_key 
}

# Stop the sing-box service
function stop_sing_box_service() {
    echo "Stop sing-box service..."
    systemctl stop sing-box

    if [[ $? -eq 0 ]]; then
        echo "sing-box service stopped."
    else
        echo -e "${RED} failed to stop sing-box service. ${NC}"
    fi
}

# Restart the sing-box service
function restart_sing_box_service() {
    echo "Restart sing-box service..."
    systemctl restart sing-box

    if [[ $? -eq 0 ]]; then
        echo "sing-box service restarted."
    else
        echo -e "${RED} failed to restart the sing-box service. ${NC}"
    fi
}

# View the sing-box service log
function view_sing_box_log() {
    echo "Checking sing-box service logs..."
    journalctl -u sing-box -f
}

# Uninstall sing-box
function uninstall_sing_box() {
    echo "Starting uninstalling sing-box..."

    stop_sing_box_service

    # Delete files and folders
    echo "Deleting files and folders..."
    rm -rf /usr/local/bin/sing-box
    rm -rf /usr/local/etc/sing-box
    rm -rf /etc/systemd/system/sing-box.service

    echo "Sing-box uninstallation completed."
}

# main menu
function main_menu() {
echo -e "${GREEN}               ------------------------------------------------------------------------------------ ${NC}"
echo -e "${GREEN} | Welcome to the Reality Installer|${NC}"
echo -e "${GREEN} | project address: https://github.com/TinrLin |${NC}"
echo -e "${GREEN}               ------------------------------------------------------------------------------------${NC}"
    echo -e "${CYAN}Please select the operation to be performed: ${NC}"
    echo -e " ${CYAN}[1]. Install sing-box service ${NC}"
    echo -e " ${CYAN}[2]. Stop sing-box service ${NC}"
    echo -e " ${CYAN}[3]. Restart sing-box service ${NC}"
    echo -e "${CYAN}[4]. View sing-box log ${NC}"
    echo -e "${CYAN}[5]. Uninstall sing-box service ${NC}"
    echo -e " ${CYAN}[0]. exit script ${NC}"

    local choice
    read -p "Please choose [1-6]: " choice

    case $choice in
        1)
            install_sing_box
            ;;
        2)
            stop_sing_box_service
            ;;
        3)
            restart_sing_box_service
            ;;
        4)
            view_sing_box_log
            ;;
        5)
            uninstall_sing_box
            ;;
        0)
            echo -e "${GREEN} Thanks for using the Reality installer script! Goodbye! ${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED} invalid selection, please re-enter. ${NC}"
            main_menu
            ;;
    esac
}

main_menu
