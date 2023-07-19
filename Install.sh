#!/bin/bash

# 安装依赖
function check_dependencies() {
    local packages=("wget" "socat" "jq" "openssl")
    
    if [[ -n $(command -v apt-get) ]]; then
        packages+=("uuid-runtime")
    elif [[ -n $(command -v yum) ]]; then
        packages+=("util-linux")
    else
        echo -e "${RED}无法确定系统包管理器，请手动安装依赖。${NC}"
        exit 1
    fi

    for package in "${packages[@]}"; do
        if ! command -v "$package" &> /dev/null; then
            echo "安装依赖: $package"
            if [[ -n $(command -v apt-get) ]]; then
                apt-get -y install "$package"
            elif [[ -n $(command -v yum) ]]; then
                yum -y install "$package"
            fi
        fi
    done
}

# 开启 BBR
function enable_bbr() {
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "开启 BBR..."
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}BBR 已开启${NC}"
    else
        echo -e "${YELLOW}BBR 已经开启，跳过配置。${NC}"
    fi
}

# 下载并安装最新的 Sing-Box 版本
function install_latest_sing_box() {
    local arch=$(uname -m)
    local url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url

    # 根据 VPS 架构确定合适的下载 URL
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
            echo "不支持的架构：$arch"
            return 1
            ;;
    esac

    # 下载并安装 Sing-Box
    if [ -n "$download_url" ]; then
        echo "正在下载 Sing-Box..."
        curl -L -o sing-box.tar.gz "$download_url"
        tar -xzf sing-box.tar.gz -C /usr/local/bin --strip-components=1
        rm sing-box.tar.gz

        # 赋予可执行权限
        chmod +x /usr/local/bin/sing-box

        echo "Sing-Box 安装成功！"
    else
        echo "无法获取 Sing-Box 的下载 URL。"
        return 1
    fi
}

# 检查防火墙配置
function check_firewall_configuration() {
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
        echo -e "${RED}无法检测到适用的防火墙配置工具，请手动配置防火墙。${NC}"
        return
    fi

    echo "检查防火墙配置..."

    case $firewall in
        ufw)
            if ! ufw status | grep -q "Status: active"; then
                ufw enable
            fi

            if ! ufw status | grep -q " $1"; then
                ufw allow "$1"
            fi

            echo "防火墙配置已更新。"
            ;;
        iptables-firewalld)
            if command -v iptables >/dev/null 2>&1; then
                if ! iptables -C INPUT -p tcp --dport "$1" -j ACCEPT >/dev/null 2>&1; then
                    iptables -A INPUT -p tcp --dport "$1" -j ACCEPT
                fi

                iptables-save > /etc/sysconfig/iptables

                echo "iptables防火墙配置已更新。"
            fi

            if command -v firewalld >/dev/null 2>&1; then
                if ! firewall-cmd --state | grep -q "running"; then
                    systemctl start firewalld
                    systemctl enable firewalld
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "$1/tcp"; then
                    firewall-cmd --zone=public --add-port="$1/tcp" --permanent
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "$1/udp"; then
                    firewall-cmd --zone=public --add-port="$1/udp" --permanent
                fi

                firewall-cmd --reload

                echo "firewalld防火墙配置已更新。"
            fi
            ;;
    esac
}

# 配置 sing-box 开机自启服务
function configure_sing_box_service() {
    echo "配置 sing-box 开机自启服务..."
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

# 检查 sing-box 文件夹是否存在，如果不存在则创建
function check_sing_box_folder() {
    local folder="/usr/local/etc/sing-box"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
    fi
}

# 生成随机 UUID
function generate_uuid() {
    local uuid=$(uuidgen)
    echo "$uuid"
}

# 生成随机 ShortId
function generate_short_id() {
    local length=$1
    local short_id=$(openssl rand -hex "$length")
    echo "$short_id"
}

# 选择流控类型
function select_flow_type() {
    local flow_type="xtls-rprx-vision"

    while true; do
        read -p "请选择流控类型：
[1]. xtls-rprx-vision
[2]. 留空
请输入选项 (默认为 xtls-rprx-vision): " flow_option

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
                echo "错误的选项，请重新输入！" >&2
                ;;
        esac
    done

    echo "$flow_type"
}

# 监听端口配置
function generate_listen_port_config() {
    local listen_port

    while true; do
        read -p "请输入监听端口 (默认为 443): " listen_port
        listen_port=${listen_port:-443}

        if ! [[ "$listen_port" =~ ^[1-9][0-9]{0,4}$ || "$listen_port" == "443" ]]; then
            echo "错误：端口范围1-65535，请重新输入！" >&2
        else
            break
        fi
    done

    echo "$listen_port"
}

# 验证服务器是否支持TLS 1.3
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

# ServerName 配置
function generate_server_name_config() {
    local server_name="www.gov.hk"

    read -p "请输入可用的 serverName 列表 (默认为 www.gov.hk): " user_input
    if [[ -n "$user_input" ]]; then
        server_name="$user_input"
        local tls13_support=$(validate_tls13_support "$server_name")

        if [[ "$tls13_support" == "false" ]]; then
            echo "该网址不支持 TLS 1.3，请重新输入！" >&2
            generate_server_name_config
            return
        fi
    fi

    echo "$server_name"
}

# 目标网站配置
function generate_target_server_config() {
    local target_server="www.gov.hk"

    read -p "请输入目标网站地址(默认为 www.gov.hk): " user_input
    if [[ -n "$user_input" ]]; then
        target_server="$user_input"
        local tls13_support=$(validate_tls13_support "$target_server")

        if [[ "$tls13_support" == "false" ]]; then
            echo "该目标网站地址不支持 TLS 1.3，请重新输入！" >&2
            generate_target_server_config
            return
        fi
    fi

    echo "$target_server"
}

# 私钥配置
function generate_private_key_config() {
    local private_key

    while true; do
        read -p "请输入私钥 (默认随机生成私钥): " private_key

        if [[ -z "$private_key" ]]; then
            local keypair_output=$(sing-box generate reality-keypair)
            private_key=$(echo "$keypair_output" | awk -F: '/PrivateKey/{gsub(/ /, "", $2); print $2}')
            echo "$keypair_output" | awk -F: '/PublicKey/{gsub(/ /, "", $2); print $2}' > /tmp/public_key_temp.txt
            break
        fi

        # 验证私钥格式是否正确
        if openssl pkey -inform PEM -noout -text -in <(echo "$private_key") >/dev/null 2>&1; then
            break
        else
            echo "无效的私钥，请重新输入！" >&2
        fi
    done
    
    echo "$private_key"
}

# ShortIds 配置
function generate_short_ids_config() {
    local short_ids=()
    local add_more_short_ids="y"
    local length=8

    while [[ "$add_more_short_ids" == "y" ]]; do
        if [[ ${#short_ids[@]} -eq 8 ]]; then
            echo "已达到最大 shortId 数量限制！" >&2
            break
        fi

        local short_id=$(generate_short_id "$length")
        short_ids+=("$short_id")

        while true; do
            read -p "是否继续添加 shortId？(y/n，默认为 n): " add_more_short_ids
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
                    echo "错误的选项，请重新输入！" >&2
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

# 流控配置
function generate_flow_config() {
    local flow_type="$1"
    local transport_config=""

    if [[ "$flow_type" != "" ]]; then
        return  
    fi

    local transport_type=""

    while true; do
        read -p "请选择传输层协议：
[1]. http
[2]. grpc
请输入选项 (默认为 http): " transport_option

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
                echo "错误的选项，请重新输入！" >&2
                ;;
        esac
    done

    transport_config='
      "transport": {
        "type": "'"$transport_type"'"
      },'

    echo "$transport_config"
}

# 用户配置
function generate_user_config() {
    local flow_type="$1"
    local users=()
    local add_more_users="y"

    while [[ "$add_more_users" == "y" ]]; do
        local user_uuid

        while true; do
            read -p "请输入用户 UUID (默认随机生成 UUID): " user_uuid

            if [[ -z "$user_uuid" ]]; then
                user_uuid=$(generate_uuid)
                break
            fi

            if [[ $user_uuid =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; then
                break
            else
                echo "无效的 UUID，请重新输入！" >&2
            fi
        done

        users+=('
        {
          "uuid": "'"$user_uuid"'",
          "flow": "'"$flow_type"'"
        },')

        while true; do
            read -p "是否继续添加用户？(y/n，默认为 n): " add_more_users
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
                    echo "错误的选项，请重新输入！" >&2
                    ;;
            esac
        done
    done

    # 去除最后一个用户配置的末尾逗号
    users[-1]=${users[-1]%,}

    echo "${users[*]}"
}

# 生成 Sing-Box 配置文件
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

    # 生成 Sing-Box 配置文件
    local config_content='{
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
    }
  ]
}'

    echo "$config_content" > "$config_file"

    echo "Sing-Box 配置文件已生成并保存至 $config_file"
    check_firewall_configuration "$listen_port"    
}

# 提取配置文件信息
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
        
        echo "监听端口: $listen_port"
        echo "用户 UUIDs:"
        echo "$users"
        echo "流控类型: $flow_type"
        echo "传输层协议: $transport_type"
        echo "serverName: $server_name"
        echo "目标网站地址: $target_server"
        echo "Short IDs:"
        echo "$short_ids"
        echo "公钥: $public_key"
}

# 启动 sing-box 服务
function start_sing_box_service() {
    echo "启动 sing-box 服务..."
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}sing-box 服务已启动。${NC}"
    else
        echo -e "${RED}启动 sing-box 服务失败。${NC}"
    fi    
}

# 安装 sing-box
function install_sing_box() {
    check_dependencies
    enable_bbr
    install_latest_sing_box
    configure_sing_box_service
    generate_sing_box_config
    start_sing_box_service
    extract_config_info_and_public_key 
}

# 停止 sing-box 服务
function stop_sing_box_service() {
    echo "停止 sing-box 服务..."
    systemctl stop sing-box

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}sing-box 服务已停止。${NC}"
    else
        echo -e "${RED}停止 sing-box 服务失败。${NC}"
    fi
}

# 重启 sing-box 服务
function restart_sing_box_service() {
    echo "重启 sing-box 服务..."
    systemctl restart sing-box

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}sing-box 服务已重启。${NC}"
    else
        echo -e "${RED}重启 sing-box 服务失败。${NC}"
    fi
}

# 查看 sing-box 服务日志
function view_sing_box_log() {
    echo "正在查看 sing-box 服务日志..."
    journalctl -u sing-box -f
}

# 卸载 sing-box
function uninstall_sing_box() {
    echo "开始卸载 sing-box..."

    stop_sing_box_service

    # 删除文件和文件夹
    echo "删除文件和文件夹..."
    rm -rf /usr/local/bin/sing-box
    rm -rf /usr/local/etc/sing-box
    rm -rf /etc/systemd/system/sing-box.service

    echo -e "${GREEN}sing-box 卸载完成。${NC}"
}

# 主菜单
function main_menu() {
echo -e "${GREEN}               ------------------------------------------------------------------------------------ ${NC}"
echo -e "${GREEN}               |                          欢迎使用 Reality 安装程序                               |${NC}"
echo -e "${GREEN}               |                      项目地址:https://github.com/TinrLin                         |${NC}"
echo -e "${GREEN}               ------------------------------------------------------------------------------------${NC}"
    echo -e "${CYAN}请选择要执行的操作：${NC}"
    echo -e "  ${CYAN}[1]. 安装 sing-box 服务${NC}"
    echo -e "  ${CYAN}[2]. 停止 sing-box 服务${NC}"
    echo -e "  ${CYAN}[3]. 重启 sing-box 服务${NC}"
    echo -e "  ${CYAN}[4]. 查看 sing-box 日志${NC}"
    echo -e "  ${CYAN}[5]. 卸载 sing-box 服务${NC}"
    echo -e "  ${CYAN}[0]. 退出脚本${NC}"

    local choice
    read -p "$(echo -e "${CYAN}请选择 [1-6]: ${NC}")" choice

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
            echo -e "${GREEN}感谢使用 Reality 安装脚本！再见！${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效的选择，请重新输入。${NC}"
            main_menu
            ;;
    esac
}

main_menu
