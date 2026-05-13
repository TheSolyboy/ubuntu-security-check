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
    local -n score_ref=$1
    local -n total_ref=$2

    echo "🔐 SSH Security Configuration:"
    local s_score=0
    local s_total=0

    local ssh_port=$(awk '/^Port/ {print $2}' /etc/ssh/sshd_config 2>/dev/null || true)
    ssh_port=${ssh_port%%$'\n'*}   # keep first line only
    if [ -n "$ssh_port" ]; then
        echo "   ✅ SSH Port: $ssh_port"
        if [ "$ssh_port" != "22" ]; then
            ((s_score+=5))
            echo "      [+5] Non-default port configured"
        fi
    else
        echo "   ⚠️  SSH Port: 22 (default)"
    fi
    ((s_total+=5))

    local root_login=$(awk '/^PermitRootLogin/ {print $2}' /etc/ssh/sshd_config 2>/dev/null || true)
    if [ "$root_login" = "no" ]; then
        echo "   ✅ Root Login: DISABLED"
        ((s_score+=10))
        echo "      [+10] Root access properly restricted"
    else
        echo "   ❌ Root Login: ENABLED"
        echo "      [-10] CRITICAL: Root login should be disabled"
    fi
    ((s_total+=10))

    local pass_auth=$(awk '/^PasswordAuthentication/ {print $2}' /etc/ssh/sshd_config 2>/dev/null || true)
    if [ "$pass_auth" = "no" ]; then
        echo "   ✅ Password Authentication: DISABLED"
        ((s_score+=15))
        echo "      [+15] Key-based authentication enforced"
    else
        echo "   ❌ Password Authentication: ENABLED"
        echo "      [-15] CRITICAL: Disable password authentication"
    fi
    ((s_total+=15))

    if systemctl is-active --quiet ssh 2>/dev/null; then
        echo "   ✅ SSH Service: ACTIVE"
        ((s_score+=5))
    else
        echo "   ❌ SSH Service: INACTIVE"
    fi
    ((s_total+=5))

    local pubkey_auth=$(awk '/^PubkeyAuthentication/ {print $2}' /etc/ssh/sshd_config 2>/dev/null || true)
    if [ "$pubkey_auth" = "yes" ]; then
        echo "   ✅ Public Key Authentication: ENABLED"
        ((s_score+=5))
    else
        echo "   ⚠️  Public Key Authentication: Default"
    fi
    ((s_total+=5))

    if [ -f ~/.ssh/authorized_keys ]; then
        local key_count=$(grep -c "^ssh-" ~/.ssh/authorized_keys 2>/dev/null || echo 0)
        echo "   ✅ Authorized Keys: $key_count configured"
        if [ "$key_count" -gt 0 ]; then
            ((s_score+=5))
        fi
    else
        echo "   ⚠️  Authorized Keys: Not configured"
    fi
    ((s_total+=5))

    local max_auth=$(awk '/^MaxAuthTries/ {print $2}' /etc/ssh/sshd_config 2>/dev/null || true)
    if [ -n "$max_auth" ] && [ "$max_auth" -le 3 ]; then
        echo "   ✅ Max Authentication Tries: $max_auth"
        ((s_score+=3))
    else
        echo "   ⚠️  Max Authentication Tries: ${max_auth:-default}"
    fi
    ((s_total+=3))

    local ssh_percentage=$((s_score * 100 / s_total))
    echo "   📊 SSH Security Score: $s_score/$s_total ($ssh_percentage%)"
    echo

    score_ref=$s_score
    total_ref=$s_total
}

analyze_firewall() {
    local -n score_ref=$1
    local -n total_ref=$2

    echo "🛡️  Firewall Configuration:"
    local f_score=0
    local f_total=0

    if command -v ufw >/dev/null 2>&1; then
        local ufw_status=$(sudo ufw status 2>/dev/null | head -1 | awk '{print $2}')
        if [ "$ufw_status" = "active" ]; then
            echo "   ✅ UFW Status: ACTIVE"
            ((f_score+=20))

            local ssh_port=$(awk '/^Port/ {print $2}' /etc/ssh/sshd_config 2>/dev/null || true)
            ssh_port=${ssh_port%%$'\n'*}
            if sudo ufw status 2>/dev/null | grep -q "${ssh_port:-22}/tcp"; then
                echo "   ✅ SSH Port: Protected"
                ((f_score+=5))
            else
                echo "   ⚠️  SSH Port: Not in firewall rules"
            fi

            local rule_count=$(sudo ufw status numbered 2>/dev/null | grep -c "^\\[" || true)
            echo "   📋 Active Rules: $rule_count"

        else
            echo "   ❌ UFW Status: INACTIVE"
            echo "      [-20] CRITICAL: Enable firewall protection"
        fi
    else
        echo "   ❌ UFW: NOT INSTALLED"
        echo "      [-20] CRITICAL: Install firewall"
    fi
    ((f_total+=25))

    local fw_percentage=$((f_score * 100 / f_total))
    echo "   📊 Firewall Score: $f_score/$f_total ($fw_percentage%)"
    echo

    score_ref=$f_score
    total_ref=$f_total
}

analyze_intrusion_prevention() {
    local -n score_ref=$1
    local -n total_ref=$2

    echo "🔨 Intrusion Prevention:"
    local i_score=0
    local i_total=0

    if command -v fail2ban-client >/dev/null 2>&1; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            echo "   ✅ Fail2Ban: ACTIVE"
            ((i_score+=15))

            local jails=$(sudo fail2ban-client status 2>/dev/null | awk -F': ' '/Jail list/ {gsub(/ /,"",$2); print $2}' || true)
            jails=${jails:-none}
            echo "   🏢 Active Jails: ${jails}"

            if [ -n "$jails" ] && [ "$jails" != "none" ]; then
                for jail in $(echo $jails | tr ',' ' '); do
                    local banned=$(sudo fail2ban-client status $jail 2>/dev/null | awk '/Currently banned/ {print $4}' || true)
                    banned=${banned:-0}
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
    ((i_total+=15))

    local ip_percentage=$((i_score * 100 / i_total))
    echo "   📊 Intrusion Prevention Score: $i_score/$i_total ($ip_percentage%)"
    echo

    score_ref=$i_score
    total_ref=$i_total
}

analyze_system_updates() {
    local -n score_ref=$1
    local -n total_ref=$2

    echo "📦 System Updates:"
    local u_score=0
    local u_total=0

    if command -v apt >/dev/null 2>&1; then
        local updates=$(apt list --upgradable 2>/dev/null | wc -l | tr -d ' ')
        local security_updates=$(apt list --upgradable 2>/dev/null | grep -c security || true)

        updates=${updates:-0}
        security_updates=${security_updates:-0}

        echo "   📋 Available Updates: $((updates-1))"
        echo "   🔒 Security Updates: $security_updates"

        if [ "$security_updates" -eq 0 ]; then
            echo "   ✅ Security Status: UP TO DATE"
            ((u_score+=15))
        else
            echo "   ❌ Security Status: $security_updates pending"
            echo "      [-15] CRITICAL: Install security updates"
        fi

        if [ "$((updates-1))" -eq 0 ]; then
            echo "   ✅ System Status: UP TO DATE"
            ((u_score+=5))
        else
            echo "   ⚠️  System Status: $((updates-1)) updates available"
        fi
    fi

    if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
        echo "   ✅ Automatic Updates: ENABLED"
        ((u_score+=5))
    else
        echo "   ⚠️  Automatic Updates: DISABLED"
    fi

    ((u_total+=25))
    local update_percentage=$((u_score * 100 / u_total))
    echo "   📊 Update Security Score: $u_score/$u_total ($update_percentage%)"
    echo

    score_ref=$u_score
    total_ref=$u_total
}

analyze_resource_usage() {
    local -n score_ref=$1
    local -n total_ref=$2

    echo "💻 System Resources:"
    local r_score=0
    local r_total=0

    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}' 2>/dev/null || true)
    cpu_usage=${cpu_usage:-0}
    echo "   🖥️  CPU Usage: ${cpu_usage}%"
    if (( $(echo "$cpu_usage < 80" | bc -l 2>/dev/null || echo 1) )); then
        ((r_score+=5))
    fi

    local mem_usage=$(free | grep Mem | awk '{printf("%.1f"), $3/$2 * 100.0}' 2>/dev/null || true)
    mem_usage=${mem_usage:-0}
    echo "   🧠 Memory Usage: ${mem_usage}%"
    if (( $(echo "$mem_usage < 85" | bc -l 2>/dev/null || echo 1) )); then
        ((r_score+=5))
    fi

    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%' 2>/dev/null || true)
    disk_usage=${disk_usage:-0}
    echo "   💾 Disk Usage: ${disk_usage}%"
    if [ "${disk_usage:-100}" -lt 85 ]; then
        ((r_score+=5))
    fi

    local load_avg=$(uptime | awk -F'load average:' '{ print $2 }' | awk '{ print $1 }' | tr -d ',' 2>/dev/null || true)
    echo "   ⚖️  Load Average: ${load_avg:-N/A}"

    ((r_total+=15))
    local resource_percentage=$((r_score * 100 / r_total))
    echo "   📊 Resource Score: $r_score/$r_total ($resource_percentage%)"
    echo

    score_ref=$r_score
    total_ref=$r_total
}

analyze_security_events() {
    local -n score_ref=$1
    local -n total_ref=$2

    echo "🔍 Security Events (24h):"
    local e_score=0
    local e_total=0

    if [ -f /var/log/auth.log ]; then
        local failed_logins=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || true)
        failed_logins=${failed_logins:-0}
        echo "   🚫 Failed Login Attempts: $failed_logins"

        if [ "$failed_logins" -lt 10 ]; then
            ((e_score+=5))
        fi

        local success_logins=$(grep -c "Accepted" /var/log/auth.log 2>/dev/null || true)
        success_logins=${success_logins:-0}
        echo "   ✅ Successful Logins: $success_logins"

        local invalid_users=$(grep -c "Invalid user" /var/log/auth.log 2>/dev/null || true)
        invalid_users=${invalid_users:-0}
        echo "   👤 Invalid User Attempts: $invalid_users"
    else
        echo "   ⚠️  Authentication logs: Not accessible"
    fi

    local uptime_info=$(uptime | awk -F'up ' '{print $2}' | awk '{print $1}')
    echo "   ⏰ System Uptime: $uptime_info"

    ((e_total+=5))
    local events_percentage=$((e_score * 100 / e_total))
    echo "   📊 Security Events Score: $e_score/$e_total ($events_percentage%)"
    echo

    score_ref=$e_score
    total_ref=$e_total
}

analyze_services() {
    local -n score_ref=$1
    local -n total_ref=$2

    echo "🛠️  Critical Services:"
    local sv_score=0
    local sv_total=0

    local critical_services=("ssh" "ufw")
    if command -v fail2ban-client >/dev/null 2>&1; then
        critical_services+=("fail2ban")
    fi

    for service in "${critical_services[@]}"; do
        if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^$service.service"; then
            if systemctl is-active --quiet $service 2>/dev/null; then
                echo "   ✅ $service: RUNNING"
                ((sv_score+=5))
            else
                echo "   ❌ $service: STOPPED"
            fi
        else
            echo "   ➖ $service: NOT INSTALLED"
        fi
        ((sv_total+=5))
    done

    local service_percentage=$((sv_score * 100 / sv_total))
    echo "   📊 Service Score: $sv_score/$sv_total ($service_percentage%)"
    echo

    score_ref=$sv_score
    total_ref=$sv_total
}

analyze_network_security() {
    local -n score_ref=$1
    local -n total_ref=$2

    echo "🌐 Network Security:"
    local n_score=0
    local n_total=0

    echo "   📡 Open Ports:"
    local listening_ports=$(sudo ss -tuln 2>/dev/null | awk 'NR>1 && /LISTEN/ {split($5,a,":"); print a[length(a)]}' | sort -n | uniq || true)

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
        ((n_score+=5))
        echo "   ✅ SSH: Non-standard port"
    fi

    ((n_total+=5))
    local network_percentage=$((n_score * 100 / n_total))
    echo "   📊 Network Security Score: $n_score/$n_total ($network_percentage%)"
    echo

    score_ref=$n_score
    total_ref=$n_total
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

    local ssh_score=0 ssh_total=0
    local fw_score=0 fw_total=0
    local ip_score=0 ip_total=0
    local update_score=0 update_total=0
    local resource_score=0 resource_total=0
    local events_score=0 events_total=0
    local service_score=0 service_total=0
    local network_score=0 network_total=0

    analyze_ssh_security ssh_score ssh_total
    analyze_firewall fw_score fw_total
    analyze_intrusion_prevention ip_score ip_total
    analyze_system_updates update_score update_total
    analyze_resource_usage resource_score resource_total
    analyze_security_events events_score events_total
    analyze_services service_score service_total
    analyze_network_security network_score network_total

    local total_score=$((ssh_score + fw_score + ip_score + update_score + resource_score + events_score + service_score + network_score))
    local total_possible=$((ssh_total + fw_total + ip_total + update_total + resource_total + events_total + service_total + network_total))
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
    local ssh_pct=$((ssh_score * 100 / ssh_total))
    local fw_pct=$((fw_score * 100 / fw_total))
    local ip_pct=$((ip_score * 100 / ip_total))
    local update_pct=$((update_score * 100 / update_total))
    generate_recommendations $overall_percentage $ssh_pct $fw_pct $ip_pct $update_pct

    echo
    echo "====================================================================="
    echo "Report completed: $(date)"
    echo "Next assessment recommended: $(date -d '+1 week')"
    echo "====================================================================="
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
