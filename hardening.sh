#!/usr/bin/env bash
# Harden Linux: permisos, deshabilitar root por SSH, instalar y configurar fail2ban.
# Uso:
#   sudo bash hardening.sh           # ejecuta cambios
#   sudo bash hardening.sh --dry-run # solo muestra lo que haría

set -euo pipefail

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

log() { echo -e "[*] $*"; }
warn() { echo -e "[!] $*" >&2; }
run() {
  if $DRY_RUN; then
    echo "DRY-RUN: $*"
  else
    eval "$@"
  fi
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    warn "Este script debe ejecutarse como root (o con sudo)."
    exit 1
  fi
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
  else
    warn "No se detectó apt/dnf/yum. Instala fail2ban manualmente."
    PKG_MGR=""
  fi
}

backup_file() {
  local f="$1"
  local dir="/root/hardening-backups"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  [[ -e "$f" ]] || return 0
  run "mkdir -p '$dir'"
  run "cp -a '$f' '$dir/$(basename "$f").$ts.bak'"
  log "Backup -> $dir/$(basename "$f").$ts.bak"
}

secure_permissions() {
  log "Ajustando permisos de archivos clave…"

  # Directorio root
  [[ -d /root ]] && run "chmod 700 /root"

  # SSH
  if [[ -f /etc/ssh/sshd_config ]]; then
    run "chown root:root /etc/ssh/sshd_config"
    run "chmod 600 /etc/ssh/sshd_config"
  fi

  # Cuentas y grupos
  [[ -f /etc/passwd ]]      && run "chmod 644 /etc/passwd"
  [[ -f /etc/group ]]       && run "chmod 644 /etc/group"
  [[ -f /etc/shadow ]]      && run "chmod 640 /etc/shadow"
  [[ -f /etc/gshadow ]]     && run "chmod 640 /etc/gshadow"

  # Sudoers
  if [[ -f /etc/sudoers ]]; then
    run "chown root:root /etc/sudoers"
    run "chmod 440 /etc/sudoers"
  fi
  if [[ -d /etc/sudoers.d ]]; then
    run "chown -R root:root /etc/sudoers.d"
    run "chmod 750 /etc/sudoers.d"
    # endurecer ficheros individuales si existen
    for f in /etc/sudoers.d/*; do
      [[ -e "$f" ]] || continue
      run "chmod 440 '$f'"
    done
  fi

  # Validar sudoers
  if command -v visudo >/dev/null 2>&1; then
    if $DRY_RUN; then
      log "Omitido 'visudo -cf' por dry-run."
    else
      if visudo -cf /etc/sudoers; then
        log "sudoers válido."
      else
        warn "¡Advertencia! /etc/sudoers tiene errores de sintaxis."
      fi
    fi
  fi
}

harden_ssh() {
  local sshd="/etc/ssh/sshd_config"
  [[ -f "$sshd" ]] || { warn "No existe $sshd; omitiendo cambios SSH."; return 0; }

  log "Deshabilitando login SSH de root…"
  backup_file "$sshd"

  # Asegurar directivas necesarias (PermitRootLogin no, y reforzar opciones comunes)
  # Usamos ediciones idempotentes
  run "sed -i 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin no/i' '$sshd'"
  grep -qi '^PermitRootLogin' "$sshd" || run "echo 'PermitRootLogin no' >> '$sshd'"

  # endurecer algunas opciones razonables sin romper (no forzamos PasswordAuthentication a no,
  # por si el servidor aún no tiene llaves distribuidas; puedes activarlo si ya usas claves).
  run "sed -i 's/^[#[:space:]]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/i' '$sshd'"
  grep -qi '^ChallengeResponseAuthentication' "$sshd" || run "echo 'ChallengeResponseAuthentication no' >> '$sshd'"

  run "sed -i 's/^[#[:space:]]*UsePAM.*/UsePAM yes/i' '$sshd'"
  grep -qi '^UsePAM' "$sshd" || run "echo 'UsePAM yes' >> '$sshd'"

  # Validar configuración antes de recargar
  if command -v sshd >/dev/null 2>&1; then
    if $DRY_RUN; then
      log "Omitido 'sshd -t' por dry-run."
    else
      if sshd -t; then
        log "sshd_config válido."
      else
        warn "¡sshd_config inválido! Revirtiendo desde backup."
        run "cp -a '/root/hardening-backups/$(basename "$sshd").'*'.bak' '$sshd'" || true
        return 1
      fi
    fi
  fi

  # Recargar servicio SSH de forma segura
  if command -v systemctl >/dev/null 2>&1; then
    run "systemctl reload sshd || systemctl reload ssh || systemctl restart sshd || systemctl restart ssh"
  else
    run "service ssh reload || service ssh restart || true"
  fi
}

install_fail2ban() {
  log "Instalando y configurando Fail2ban…"
  detect_pkg_mgr

  case "$PKG_MGR" in
    apt)
      run "apt-get update -y"
      run "DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban"
      ;;
    dnf)
      run "dnf install -y fail2ban"
      ;;
    yum)
      run "yum install -y epel-release || true"
      run "yum install -y fail2ban"
      ;;
    *)
      warn "No se pudo instalar fail2ban automáticamente (sin gestor)."
      return 0
      ;;
  esac

  # Crear jail.local básica para proteger SSH
  local jaild="/etc/fail2ban"
  local jail_local="$jaild/jail.local"
  backup_file "$jail_local"

  run "mkdir -p '$jaild'"

  # Configuración sobria y segura (puedes ajustar bantime/findtime/maxretry)
  run "bash -c 'cat > \"$jail_local\" <<\"EOF\"
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
destemail = root@localhost
sender = fail2ban@$(hostname -f 2>/dev/null || hostname)
action = %(action_mwl)s

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = systemd
EOF'"

  # Habilitar y arrancar
  if command -v systemctl >/dev/null 2>&1; then
    run "systemctl enable fail2ban"
    run "systemctl restart fail2ban"
    run "systemctl status --no-pager --full fail2ban || true"
  else
    run "service fail2ban restart || true"
  fi

  # Mostrar estado de la jail sshd (si fail2ban-client existe)
  if command -v fail2ban-client >/dev/null 2>&1; then
    run "fail2ban-client status || true"
    run "fail2ban-client status sshd || true"
  fi
}

preflight_warnings() {
  # Avisar si no hay usuarios sudo alternativos antes de bloquear root por SSH
  if command -v getent >/dev/null 2>&1; then
    # Buscar usuarios en grupo sudo/wheel (según distro)
    local sudoers_count=0
    if getent group sudo >/dev/null; then
      sudoers_count=$(getent group sudo | awk -F: '{print $4}' | awk -F, '{print NF}')
    elif getent group wheel >/dev/null; then
      sudoers_count=$(getent group wheel | awk -F: '{print $4}' | awk -F, '{print NF}')
    fi
    if [[ "${sudoers_count:-0}" -eq 0 ]]; then
      warn "No se detectan usuarios no-root con privilegios sudo/wheel. Asegúrate de tener al menos uno antes de cerrar root por SSH."
    fi
  fi
}

main() {
  require_root
  preflight_warnings
  secure_permissions
  harden_ssh
  install_fail2ban
  log "Listo. Revisa /root/hardening-backups para respaldos y 'fail2ban-client status sshd' para estado."
}

main "$@"
