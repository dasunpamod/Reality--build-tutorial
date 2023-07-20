# **illustrate**
### The script supports multiple users and custom ports; supports the construction of vless+vision+reality and vless+h2/grpc+reality
### The script supports CentOS 8+, Debian 10+, Ubuntu 20+ operating systems.
### All codes are from official documentation;The script is completely open source,you can use it with confidence!
# **Script installation**
#### Debian && Ubuntu
```
apt update && apt -y install curl
```
#### CentOS
```
yum update && yum -y install curl
```
### Install
```
bash <(curl -L https://raw.githubusercontent.com/TinrLin/Reality--build-tutorial/main/Install.sh)
```
# **Manual installation**
- **Install the sing-box program**
#### Debian && Ubuntu
##### AMD
```
apt -y update && apt -y install wget && wget -O /usr/local/bin/tuic https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-x86_64-unknown-linux-gnu && chmod +x /usr/local/bin/tuic
