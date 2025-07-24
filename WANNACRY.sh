#!/bin/bash
# Create logs directory if not exists
mkdir -p logs

# Check if required tools are installed
for tool in figlet lolcat nmap hping3 gobuster hydra ss journalctl tail find ip; do
  if ! command -v $tool &> /dev/null; then
    echo "$tool is required but not installed. Install it and rerun."
    exit 1
  fi
done

function show_home() {
  clear
  figlet -f slant "Choose Your Side" | lolcat
  echo -e "\n\e[36m1) Red Team (Offensive Tools)\e[0m"
  echo -e "\e[34m2) Blue Team (Defensive Tools)\e[0m"
  echo -e "\e[97m3) SOC Mode (Monitoring & Response)\e[0m"
  echo -e "\nPress Q to quit anytime."
  read -p $'\nChoose [1-3 or Q]: ' team_choice

  if [[ "$team_choice" =~ ^[Qq]$ ]]; then
    echo "Goodbye."
    clear
    exit 0
  fi
}

function post_action_menu() {
  echo -e "\nWhat do you want to do next?"
  echo "1) Go back to main menu"
  echo "2) Exit to home page"
  read -p "Choose [1-2 or Q to quit]: " next_choice
  case $next_choice in
    1) exec "$0" ;;
    2) main_loop ;;
    [Qq]) echo "Goodbye."; clear; exit 0 ;;
    *) echo "Invalid choice, returning to home page."; main_loop ;;
  esac
}

# Status updater for nmap: check log size or output file size as proxy for progress
function monitor_nmap() {
  local logfile="$1"
  while kill -0 "$2" 2>/dev/null; do
    sleep 30
    if [[ -f "$logfile" ]]; then
      local lines=$(wc -l < "$logfile")
      echo "[Status] nmap output lines: $lines"
    fi
  done
}

# Status updater for gobuster: count lines in output file (each line is a path found)
function monitor_gobuster() {
  local logfile="$1"
  while kill -0 "$2" 2>/dev/null; do
    sleep 30
    if [[ -f "$logfile" ]]; then
      local lines=$(wc -l < "$logfile")
      echo "[Status] Gobuster found $lines entries so far..."
    fi
  done
}

# Status updater for hydra: parse hydra output file for password attempts
function monitor_hydra() {
  local logfile="$1"
  while kill -0 "$2" 2>/dev/null; do
    sleep 30
    if [[ -f "$logfile" ]]; then
      local tries=$(grep -c 'login:' "$logfile" 2>/dev/null || echo 0)
      echo "[Status] Hydra password attempts recorded: $tries"
    fi
  done
}

function get_local_subnet() {
  local ip addr subnet
  # Detect primary interface IP (IPv4) ignoring loopback
  ip=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | head -n1)
  if [[ -z "$ip" ]]; then
    echo ""
    return 1
  fi
  echo "$ip"
}

function get_network_cidr() {
  local cidr
  cidr=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | head -n1)
  if [[ -z "$cidr" ]]; then
    echo ""
    return 1
  fi
  echo "$cidr"
}

function red_team_menu() {
  clear
  echo -e "\e[31m"
  figlet -f big "WANNACRY?"
  echo -e "\e[0m"
  echo -e "\nFor educational purposes only.\n"
  echo -e "Press Q to quit anytime.\n"

  echo -e "Choose an option:"
  echo "1) Scan Ports"
  echo "2) DDoS Attack"
  echo "3) Scan Website for Hidden Pages"
  echo "4) Brute Force Attack"
  echo "5) Exit to home page"
  read -p "Select an option [1-5 or Q]: " choice

  if [[ "$choice" =~ ^[Qq]$ ]]; then
    main_loop
  fi

  case $choice in
    1)
      read -p "Enter target IP or domain (or 'Q' to cancel): " target
      [[ "$target" =~ ^[Qq]$ ]] && main_loop
      echo -e "\nRunning Port Scan on $target...\n"
      logfile="logs/nmap_output.txt"
      nmap -sC -sV -p- "$target" -T4 > "$logfile" 2>/dev/null &
      nmap_pid=$!
      monitor_nmap "$logfile" $nmap_pid
      wait $nmap_pid
      echo -e "\nScan complete. Output saved to $logfile"
      post_action_menu
      ;;
    2)
      read -p "Enter target IP (or 'Q' to cancel): " target
      [[ "$target" =~ ^[Qq]$ ]] && main_loop
      read -p "Enter number of packets to send (e.g. 1000): " count
      echo -e "\nLaunching test traffic flood on $target...\n"
      sudo hping3 -S --flood -c "$count" "$target" > /dev/null 2>&1 &
      wait
      echo "Flood complete."
      post_action_menu
      ;;
    3)
      read -p "Enter website IP or domain (or 'Q' to cancel): " website
      [[ "$website" =~ ^[Qq]$ ]] && main_loop
      read -p "Enter wordlist path (e.g. /usr/share/wordlists/dirb/common.txt): " wordlist
      [[ "$wordlist" =~ ^[Qq]$ ]] && main_loop

      if [[ ! -f "$wordlist" ]]; then
        echo "Error: Wordlist file not found!"
        post_action_menu
        return
      fi

      if [[ "$website" != http* ]]; then
        website="http://$website"
      fi

      echo -e "\nScanning for hidden pages on $website...\n"
      logfile="logs/gobuster_output.txt"
      gobuster dir -u "$website" -w "$wordlist" -q > "$logfile" 2>/dev/null &
      gobuster_pid=$!
      monitor_gobuster "$logfile" $gobuster_pid
      wait $gobuster_pid
      echo -e "\nScan complete. Output saved to $logfile"
      post_action_menu
      ;;
    4)
      echo -e "\nSelect service to attack:"
      echo "1) SSH"
      echo "2) FTP"
      echo "3) HTTP Login"
      read -p "Choose [1-3] (or 'Q' to cancel): " svc
      [[ "$svc" =~ ^[Qq]$ ]] && main_loop

      case $svc in
        1) service="ssh" ;;
        2) service="ftp" ;;
        3) service="http-get" ;;
        *) echo "Invalid selection."; post_action_menu; return ;;
      esac

      read -p "Enter IP or domain: " target
      [[ "$target" =~ ^[Qq]$ ]] && main_loop
      read -p "Enter username: " user
      [[ "$user" =~ ^[Qq]$ ]] && main_loop
      read -p "Enter password wordlist: " wordlist
      [[ "$wordlist" =~ ^[Qq]$ ]] && main_loop

      if [[ ! -f "$wordlist" ]]; then
        echo "Error: Wordlist file not found!"
        post_action_menu
        return
      fi

      echo -e "\nRunning password attack on $target ($service)...\n"
      logfile="logs/hydra_output.txt"
      hydra -l "$user" -P "$wordlist" "$target" "$service" > "$logfile" 2>/dev/null &
      hydra_pid=$!
      monitor_hydra "$logfile" $hydra_pid
      wait $hydra_pid
      echo -e "\nAttack complete. Output saved to $logfile"
      post_action_menu
      ;;
    5)
      main_loop
      ;;
    *)
      echo "Invalid option."
      post_action_menu
      ;;
  esac
}

function blue_team_menu() {
  clear
  echo -e "\e[34m"
  figlet -f big "WANNACRY?"
  echo -e "\e[0m"
  echo -e "\nBlue Team — Defensive Toolkit\n"
  echo "1) Scan local machine for open ports"
  echo "2) Discover live hosts on local network"
  echo "3) Show active listening services"
  echo "4) View system logs (last 50 lines)"
  echo "5) Exit to home page"
  echo -e "Press Q to quit anytime."
  read -p "Select an option [1-5 or Q]: " blue_choice

  if [[ "$blue_choice" =~ ^[Qq]$ ]]; then
    main_loop
  fi

  case $blue_choice in
    1)
      echo -e "\nScanning local machine (localhost)...\n"
      logfile="logs/blue_local_scan.txt"
      sudo nmap -sS -T4 localhost > "$logfile" 2>/dev/null &
      nmap_pid=$!
      monitor_nmap "$logfile" $nmap_pid
      wait $nmap_pid
      echo "Scan complete. Output saved to $logfile"
      post_action_menu
      ;;
    2)
      # Automatically detect local network subnet
      subnet=$(get_network_cidr)
      if [[ -z "$subnet" ]]; then
        echo "Could not detect local subnet automatically."
        post_action_menu
        return
      fi
      echo -e "\nScanning network $subnet for live hosts...\n"
      logfile="logs/blue_network_scan.txt"
      sudo nmap -sn "$subnet" > "$logfile" 2>/dev/null &
      nmap_pid=$!
      monitor_nmap "$logfile" $nmap_pid
      wait $nmap_pid
      echo "Scan complete. Output saved to $logfile"
      post_action_menu
      ;;
    3)
      echo -e "\nChecking for active listening services...\n"
      ss -tuln
      post_action_menu
      ;;
    4)
      echo -e "\nShowing system logs (last 50 lines)...\n"
      journalctl -xe | tail -n 50
      post_action_menu
      ;;
    5)
      main_loop
      ;;
    *)
      echo "Invalid option. Returning to home page."
      main_loop
      ;;
  esac
}

function soc_mode_menu() {
  clear
  echo -e "\e[97m"
  figlet -f big "WANNACRY?"
  echo -e "\e[0m"
  echo -e "\nSOC Mode — Monitoring & Response\n"
  echo "1) Check for suspicious open ports (Blue)"
  echo "2) View authentication logs (Blue)"
  echo "3) Fast scan external target (Red)"
  echo "4) Find readable config files (Red)"
  echo "5) Exit to home page"
  echo -e "Press Q to quit anytime."
  read -p "Select an option [1-5 or Q]: " soc_choice

  if [[ "$soc_choice" =~ ^[Qq]$ ]]; then
    main_loop
  fi

  case $soc_choice in
    1)
      echo -e "\nChecking for suspicious open ports...\n"
      sudo nmap -Pn -sS -T3 localhost -p- --open | tee logs/soc_ports.txt
      post_action_menu
      ;;
    2)
      echo -e "\nTailing authentication logs (last 20 login attempts)...\n"
      sudo journalctl _COMM=sshd | tail -n 20 | tee logs/soc_auth_logs.txt
      post_action_menu
      ;;
    3)
      read -p "Enter external IP or domain to scan (or Q to cancel): " external_target
      [[ "$external_target" =~ ^[Qq]$ ]] && main_loop
      echo -e "\nRunning fast scan on $external_target...\n"
      sudo nmap -F "$external_target" | tee logs/soc_fast_scan.txt
      post_action_menu
      ;;
    4)
      echo -e "\nFinding readable .conf or .env files in /etc...\n"
      sudo find /etc \( -name "*.conf" -o -name "*.env" \) -readable 2>/dev/null | tee logs/soc_config_files.txt
      post_action_menu
      ;;
    5)
      main_loop
      ;;
    *)
      echo "Invalid option. Returning to home page."
      main_loop
      ;;
  esac
}

function main_loop() {
  while true; do
    show_home
    case $team_choice in
      1) red_team_menu ;;
      2) blue_team_menu ;;
      3) soc_mode_menu ;;
      *) echo "Invalid choice. Try again." ;;
    esac
  done
}

main_loop







































































































