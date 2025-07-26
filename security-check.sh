#!/bin/bash

# Server Security Assessment Tool
# Comprehensive security analysis for Linux servers
# Author: System Administrator
# Version: 2.1.0
# License: MIT

set -euo pipefail

SCRIPT_VERSION="2.1.0"
REPORT_DATE=$(date)
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
OS_INFO=$(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown Linux Distribution")

print_header() {
    echo "====================================================================="
    echo "                    SECURITY ASSESSMENT REPORT"
    echo "====================================================================="
    echo "Generated: $REPORT_DATE"
    echo "Hostname: $HOSTNAME"
    echo "Kernel: $KERNEL"
    echo "OS: $OS_INFO"
    echo "Script Version: $SCRIPT_VERSION"
    echo
}

analyze_ssh_security() {
    echo "🔐 SSH Security Configuration:"
    local ssh_score=0
    local ssh_total=0
    
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$ssh_port" ]; then
        echo "   ✅ SSH Port: $ssh_port"
        if [ "$ssh_port" != "22" ]; then
            ((ssh_score+=5))
            echo "      [+5] Non-default port configured"
        fi
    else
        echo "   ⚠️  SSH Port: 22 (default)"
    fi
    ((ssh_total+=5))

    local root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$root_login" = "no" ]; then
        echo "   ✅ Root Login: DISABLED"
        ((ssh_score+=10))
        echo "      [+10] Root access properly restricted"
    else
        echo "   ❌ Root Login: ENABLED"
        echo "      [-10] CRITICAL: Root login should be disabled"
    fi
    ((ssh_total+=10))

    local pass_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$pass_auth" = "no" ]; then
        echo "   ✅ Password Authentication: DISABLED"
        ((ssh_score+=15))
        echo "      [+15] Key-based authentication enforced"
    else
        echo "   ❌ Password Authentication: ENABLED"
        echo "      [-15] CRITICAL: Disable password authentication"
    fi
    ((ssh_total+=15))

    if systemctl is-active --quiet ssh 2>/dev/null; then
        echo "   ✅ SSH Service: ACTIVE"
        ((ssh_score+=5))
    else
        echo "   ❌ SSH Service: INACTIVE"
    fi
    ((ssh_total+=5))

    local pubkey_auth=$(grep "^PubkeyAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$pubkey_auth" = "yes" ]; then
        echo "   ✅ Public Key Authentication: ENABLED"
        ((ssh_score+=5))
    else
        echo "   ⚠️  Public Key Authentication: Default"
    fi
    ((ssh_total+=5))

    if [ -f ~/.ssh/authorized_keys ]; then
        local key_count=$(grep -c "^ssh-" ~/.ssh/authorized_keys 2>/dev/null || echo 0)
        echo "   ✅ Authorized Keys: $key_count configured"
        if [ "$key_count" -gt 0 ]; then
            ((ssh_score+=5))
        fi
    else
        echo "   ⚠️  Authorized Keys: Not configured"
    fi
    ((ssh_total+=5))

    local max_auth=$(grep "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$max_auth" ] && [ "$max_auth" -le 3 ]; then
        echo "   ✅ Max Authentication Tries: $max_auth"
        ((ssh_score+=3))
    else
        echo "   ⚠️  Max Authentication Tries: ${max_auth:-default}"
    fi
    ((ssh_total+=3))

    local ssh_percentage=$((ssh_score * 100 / ssh_total))
    echo "   📊 SSH Security Score: $ssh_score/$ssh_total ($ssh_percentage%)"
    echo
    
    echo "$ssh_score $ssh_total"
}

analyze_firewall() {
    echo "🛡️  Firewall Configuration:"
    local fw_score=0
    local fw_total=0

    if command -v ufw >/dev/null 2>&1; then
        local ufw_status=$(sudo ufw status 2>/dev/null | head -1 | awk '{print $2}')
        if [ "$ufw_status" = "active" ]; then
            echo "   ✅ UFW Status: ACTIVE"
            ((fw_score+=20))
            
            local ssh_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
            if sudo ufw status 2>/dev/null | grep -q "${ssh_port:-22}/tcp"; then
                echo "   ✅ SSH Port: Protected"
                ((fw_score+=5))
            else
                echo "   ⚠️  SSH Port: Not in firewall rules"
            fi
            
            local rule_count=$(sudo ufw status numbered 2>/dev/null | grep -c "^\[" || echo 0)
            echo "   📋 Active Rules: $rule_count"
            
        else
            echo "   ❌ UFW Status: INACTIVE"
            echo "      [-20] CRITICAL: Enable firewall protection"
        fi
    else
        echo "   ❌ UFW: NOT INSTALLED"
        echo "      [-20] CRITICAL: Install firewall"
    fi
    ((fw_total+=25))

    local fw_percentage=$((fw_score * 100 / fw_total))
    echo "   📊 Firewall Score: $fw_score/$fw_total ($fw_percentage%)"
    echo
    
    echo "$fw_score $fw_total"
}

analyze_intrusion_prevention() {
    echo "🔨 Intrusion Prevention:"
    local ip_score=0
    local ip_total=0

    if command -v fail2ban-client >/dev/null 2>&1; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            echo "   ✅ Fail2Ban: ACTIVE"
            ((ip_score+=15))
            
            local jails=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d ' ' || echo "none")
            echo "   🏢 Active Jails: ${jails}"
            
            if [ -n "$jails" ] && [ "$jails" != "none" ]; then
                for jail in $(echo $jails | tr ',' ' '); do
                    local banned=$(sudo fail2ban-client status $jail 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo "0")
                    echo "   🚫 Banned IPs ($jail): ${banned}"
                done
            fi
            
        else
            echo "   ❌ Fail2Ban: INSTALLED (not running)"
        fi
    else
        echo "   ❌ Fail2Ban: NOT INSTALLED"
        echo "      [-15] CRITICAL: Install Fail2Ban"
    fi
    ((ip_total+=15))

    local ip_percentage=$((ip_score * 100 / ip_total))
    echo "   📊 Intrusion Prevention Score: $ip_score/$ip_total ($ip_percentage%)"
    echo
    
    echo "$ip_score $ip_total"
}

analyze_system_updates() {
    echo "📦 System Updates:"
    local update_score=0
    local update_total=0

    if command -v apt >/dev/null 2>&1; then
        local updates=$(apt list --upgradable 2>/dev/null | wc -l)
        local security_updates=$(apt list --upgradable 2>/dev/null | grep security | wc -l || echo 0)
        
        echo "   📋 Available Updates: $((updates-1))"
        echo "   🔒 Security Updates: $security_updates"
        
        if [ "$security_updates" -eq 0 ]; then
            echo "   ✅ Security Status: UP TO DATE"
            ((update_score+=15))
        else
            echo "   ❌ Security Status: $security_updates pending"
            echo "      [-15] CRITICAL: Install security updates"
        fi
        
        if [ "$((updates-1))" -eq 0 ]; then
            echo "   ✅ System Status: UP TO DATE"
            ((update_score+=5))
        else
            echo "   ⚠️  System Status: $((updates-1)) updates available"
        fi
    fi

    if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
        echo "   ✅ Automatic Updates: ENABLED"
        ((update_score+=5))
    else
        echo "   ⚠️  Automatic Updates: DISABLED"
    fi

    ((update_total+=25))
    local update_percentage=$((update_score * 100 / update_total))
    echo "   📊 Update Security Score: $update_score/$update_total ($update_percentage%)"
    echo
    
    echo "$update_score $update_total"
}

analyze_resource_usage() {
    echo "💻 System Resources:"
    local resource_score=0
    local resource_total=0

    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}' 2>/dev/null || echo "0")
    echo "   🖥️  CPU Usage: ${cpu_usage}%"
    if (( $(echo "$cpu_usage < 80" | bc -l 2>/dev/null || echo 1) )); then
        ((resource_score+=5))
    fi

    local mem_usage=$(free | grep Mem | awk '{printf("%.1f"), $3/$2 * 100.0}' 2>/dev/null || echo "0")
    echo "   🧠 Memory Usage: ${mem_usage}%"
    if (( $(echo "$mem_usage < 85" | bc -l 2>/dev/null || echo 1) )); then
        ((resource_score+=5))
    fi

    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%' 2>/dev/null || echo "0")
    echo "   💾 Disk Usage: ${disk_usage}%"
    if [ "${disk_usage:-100}" -lt 85 ]; then
        ((resource_score+=5))
    fi

    local load_avg=$(uptime | awk -F'load average:' '{ print $2 }' | awk '{ print $1 }' | tr -d ',' 2>/dev/null || echo "0")
    echo "   ⚖️  Load Average: $load_avg"

    ((resource_total+=15))
    local resource_percentage=$((resource_score * 100 / resource_total))
    echo "   📊 Resource Score: $resource_score/$resource_total ($resource_percentage%)"
    echo
    
    echo "$resource_score $resource_total"
}

analyze_security_events() {
    echo "🔍 Security Events (24h):"
    local events_score=0
    local events_total=0

    if [ -f /var/log/auth.log ]; then
        local failed_logins=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l || echo 0)
        echo "   🚫 Failed Login Attempts: $failed_logins"
        
        if [ "$failed_logins" -lt 10 ]; then
            ((events_score+=5))
        fi
        
        local success_logins=$(grep "Accepted" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l || echo 0)
        echo "   ✅ Successful Logins: $success_logins"
        
        local invalid_users=$(grep "Invalid user" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l || echo 0)
        echo "   👤 Invalid User Attempts: $invalid_users"
    else
        echo "   ⚠️  Authentication logs: Not accessible"
    fi

    local uptime_info=$(uptime | awk -F'up ' '{print $2}' | awk '{print $1}')
    echo "   ⏰ System Uptime: $uptime_info"

    ((events_total+=5))
    local events_percentage=$((events_score * 100 / events_total))
    echo "   📊 Security Events Score: $events_score/$events_total ($events_percentage%)"
    echo
    
    echo "$events_score $events_total"
}

analyze_services() {
    echo "🛠️  Critical Services:"
    local service_score=0
    local service_total=0

    local critical_services=("ssh" "ufw")
    if command -v fail2ban-client >/dev/null 2>&1; then
        critical_services+=("fail2ban")
    fi

    for service in "${critical_services[@]}"; do
        if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^$service.service"; then
            if systemctl is-active --quiet $service 2>/dev/null; then
                echo "   ✅ $service: RUNNING"
                ((service_score+=5))
            else
                echo "   ❌ $service: STOPPED"
            fi
        else
            echo "   ➖ $service: NOT INSTALLED"
        fi
        ((service_total+=5))
    done

    local service_percentage=$((service_score * 100 / service_total))
    echo "   📊 Service Score: $service_score/$service_total ($service_percentage%)"
    echo
    
    echo "$service_score $service_total"
}

analyze_network_security() {
    echo "🌐 Network Security:"
    local network_score=0
    local network_total=0

    echo "   📡 Open Ports:"
    local listening_ports=$(sudo netstat -tuln 2>/dev/null | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -n | uniq)
    
    for port in $listening_ports; do
        case $port in
            22|2222) echo "      SSH: $port ✅" ;;
            80) echo "      HTTP: $port ⚠️" ;;
            443) echo "      HTTPS: $port ✅" ;;
            3000|3443) echo "      Application: $port ✅" ;;
            53) echo "      DNS: $port ⚠️" ;;
            *) echo "      Service: $port ⚠️" ;;
        esac
    done

    if echo "$listening_ports" | grep -q "^2222$" && ! echo "$listening_ports" | grep -q "^22$"; then
        ((network_score+=5))
        echo "   ✅ SSH: Non-standard port"
    fi

    ((network_total+=5))
    local network_percentage=$((network_score * 100 / network_total))
    echo "   📊 Network Security Score: $network_score/$network_total ($network_percentage%)"
    echo
    
    echo "$network_score $network_total"
}

generate_recommendations() {
    local overall_score=$1
    local ssh_score=$2
    local fw_score=$3
    local ip_score=$4
    local update_score=$5
    
    echo "====================================================================="
    echo "                         RECOMMENDATIONS"
    echo "====================================================================="
    
    if [ $ssh_score -lt 80 ]; then
        echo "🔴 HIGH PRIORITY - SSH Security:"
        echo "   • Disable root login in /etc/ssh/sshd_config"
        echo "   • Disable password authentication"
        echo "   • Configure SSH key authentication"
    fi

    if [ $fw_score -lt 80 ]; then
        echo "🔴 HIGH PRIORITY - Firewall:"
        echo "   • sudo ufw enable"
        echo "   • Configure appropriate rules"
    fi

    if [ $ip_score -lt 80 ]; then
        echo "🔴 HIGH PRIORITY - Intrusion Prevention:"
        echo "   • sudo apt install fail2ban"
        echo "   • sudo systemctl enable fail2ban"
    fi

    if [ $update_score -lt 80 ]; then
        echo "🔴 HIGH PRIORITY - System Updates:"
        echo "   • sudo apt update && sudo apt upgrade"
        echo "   • Configure automatic security updates"
    fi

    if [ $overall_score -ge 85 ]; then
        echo "✅ EXCELLENT SECURITY POSTURE"
        echo
        echo "🚀 Advanced Security Enhancements:"
        echo "   • Implement intrusion detection (AIDE/OSSEC)"
        echo "   • Configure centralized logging"
        echo "   • Set up SSL/TLS certificates"
        echo "   • Establish backup and disaster recovery"
        echo "   • Regular penetration testing"
    fi
}

main() {
    print_header
    
    ssh_results=($(analyze_ssh_security))
    fw_results=($(analyze_firewall))
    ip_results=($(analyze_intrusion_prevention))
    update_results=($(analyze_system_updates))
    resource_results=($(analyze_resource_usage))
    events_results=($(analyze_security_events))
    service_results=($(analyze_services))
    network_results=($(analyze_network_security))
    
    local total_score=$((${ssh_results[0]} + ${fw_results[0]} + ${ip_results[0]} + ${update_results[0]} + ${resource_results[0]} + ${events_results[0]} + ${service_results[0]} + ${network_results[0]}))
    local total_possible=$((${ssh_results[1]} + ${fw_results[1]} + ${ip_results[1]} + ${update_results[1]} + ${resource_results[1]} + ${events_results[1]} + ${service_results[1]} + ${network_results[1]}))
    local overall_percentage=$((total_score * 100 / total_possible))

    echo "====================================================================="
    echo "                      SECURITY ASSESSMENT"
    echo "====================================================================="
    echo "🏆 Overall Security Score: $total_score/$total_possible ($overall_percentage%)"
    echo

    if [ $overall_percentage -ge 90 ]; then
        echo "🟢 STATUS: EXCELLENT SECURITY"
    elif [ $overall_percentage -ge 75 ]; then
        echo "🟡 STATUS: GOOD SECURITY"
    elif [ $overall_percentage -ge 50 ]; then
        echo "🟠 STATUS: MODERATE SECURITY"
    else
        echo "🔴 STATUS: POOR SECURITY - IMMEDIATE ACTION REQUIRED"
    fi
    
    echo
    generate_recommendations $overall_percentage $((${ssh_results[0]} * 100 / ${ssh_results[1]})) $((${fw_results[0]} * 100 / ${fw_results[1]})) $((${ip_results[0]} * 100 / ${ip_results[1]})) $((${update_results[0]} * 100 / ${update_results[1]}))
    
    echo
    echo "====================================================================="
    echo "Report completed: $(date)"
    echo "Next assessment recommended: $(date -d '+1 week')"
    echo "====================================================================="
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
