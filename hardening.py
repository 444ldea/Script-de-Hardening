#!/usr/bin/env python3
"""
Hardening básico de servidores Linux:
- Ajusta permisos de archivos sensibles (/etc/{passwd,group,shadow,gshadow}, sudoers, sshd_config, /root)
- Deshabilita el login SSH de root (PermitRootLogin no) y refuerza opciones comunes
- Instala y configura Fail2ban con una jail para sshd

Uso:
  sudo python3 hardening.py                 # aplica cambios
  sudo python3 hardening.py --dry-run       # simula sin aplicar cambios

Opciones útiles:
  --password-auth {yes,no,keep}   (por defecto: keep -> no tocar PasswordAuthentication)
  --no-fail2ban                   (omite la instalación/configuración de fail2ban)
  --bantime 1h --findtime 10m --maxretry 5 --destemail root@localhost
"""

from __future__ import annotations
import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Optional

# -------------------------
# Utilidades
# -------------------------

def log(msg: str) -> None:
    print(f"[*] {msg}")

def warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)

def run_cmd(cmd: list[str], dry_run: bool = False, check: bool = True) -> subprocess.CompletedProcess | None:
    """
    Ejecuta un comando (lista). En dry-run, solo lo muestra.
    """
    if dry_run:
        print("DRY-RUN:", " ".join(cmd))
        return None
    try:
        return subprocess.run(cmd, check=check, text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        warn(f"Comando falló: {' '.join(cmd)}\nSTDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}")
        if check:
            raise
        return e

def require_root() -> None:
    if os.geteuid() != 0:
        warn("Este script debe ejecutarse como root (o con sudo).")
        sys.exit(1)

def detect_pkg_mgr() -> str:
    for mg in ("apt-get", "dnf", "yum"):
        if shutil.which(mg):
            return mg
    return ""

def backup_file(path: str, dry_run: bool = False) -> Optional[str]:
    """
    Crea backup en /root/hardening-backups/<nombre>.<timestamp>.bak
    Devuelve la ruta del backup o None si archivo no existe.
    """
    if not os.path.exists(path):
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    dest_dir = "/root/hardening-backups"
    backup_path = os.path.join(dest_dir, f"{os.path.basename(path)}.{ts}.bak")
    if dry_run:
        print(f"DRY-RUN: cp -a '{path}' '{backup_path}'")
        return backup_path
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copy2(path, backup_path)
    log(f"Backup -> {backup_path}")
    return backup_path

def set_permissions(path: str, mode: int, owner_uid: int = 0, owner_gid: int = 0, dry_run: bool = False) -> None:
    if not os.path.exists(path):
        return
    if dry_run:
        print(f"DRY-RUN: chown {owner_uid}:{owner_gid} '{path}' && chmod {oct(mode)} '{path}'")
        return
    try:
        os.chown(path, owner_uid, owner_gid)
    except PermissionError:
        warn(f"No se pudo cambiar propietario de {path} (permiso).")
    except Exception as e:
        warn(f"No se pudo cambiar propietario de {path}: {e}")
    try:
        os.chmod(path, mode)
    except Exception as e:
        warn(f"No se pudo cambiar permisos de {path}: {e}")

def edit_sshd_config_key(sshd_path: str, key: str, value: str, dry_run: bool = False) -> None:
    """
    Asegura que 'key value' esté presente en sshd_config:
      - Reemplaza líneas existentes (aunque estén comentadas)
      - Si no existe, la añade al final
    Idempotente.
    """
    if not os.path.exists(sshd_path):
        warn(f"No existe {sshd_path}")
        return

    with open(sshd_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s+.*$", re.IGNORECASE | re.MULTILINE)
    new_line = f"{key} {value}"

    if re.search(pattern, content):
        new_content = re.sub(pattern, new_line, content)
    else:
        new_content = content
        if not content.endswith("\n"):
            new_content += "\n"
        new_content += new_line + "\n"

    if dry_run:
        print(f"DRY-RUN: set '{key} {value}' en {sshd_path}")
        return

    with open(sshd_path, "w", encoding="utf-8") as f:
        f.write(new_content)

def has_systemctl() -> bool:
    return shutil.which("systemctl") is not None

def service_reload_or_restart(names: list[str], dry_run: bool = False) -> None:
    """
    Intenta reload, si falla hace restart. Prueba nombres alternativos.
    """
    for name in names:
        if has_systemctl():
            # reload
            res = run_cmd(["systemctl", "reload", name], dry_run=dry_run, check=False)
            if (res is None) or (res and res.returncode == 0):
                return
            # restart
            res = run_cmd(["systemctl", "restart", name], dry_run=dry_run, check=False)
            if (res is None) or (res and res.returncode == 0):
                return
        else:
            res = run_cmd(["service", name, "reload"], dry_run=dry_run, check=False)
            if (res is None) or (res and res.returncode == 0):
                return
            res = run_cmd(["service", name, "restart"], dry_run=dry_run, check=False)
            if (res is None) or (res and res.returncode == 0):
                return

# -------------------------
# Pasos de hardening
# -------------------------

def preflight_warnings() -> None:
    """
    Avisa si no hay usuarios sudo/wheel (riesgo al deshabilitar root por SSH).
    """
    try:
        import grp  # noqa
        sudo_members = []
        try:
            sudo_members = grp.getgrnam("sudo").gr_mem  # type: ignore
        except KeyError:
            pass
        wheel_members = []
        try:
            wheel_members = grp.getgrnam("wheel").gr_mem  # type: ignore
        except KeyError:
            pass
        if not sudo_members and not wheel_members:
            warn("No se detectan usuarios no-root en grupos sudo/wheel. "
                 "Asegúrate de tener al menos uno antes de bloquear root por SSH.")
    except Exception:
        # Si falla la detección, solo avisamos.
        warn("No se pudo verificar usuarios con privilegios (sudo/wheel). Continúa con precaución.")

def secure_permissions(dry_run: bool = False) -> None:
    log("Ajustando permisos de archivos clave…")
    if os.path.isdir("/root"):
        set_permissions("/root", 0o700, dry_run=dry_run)

    if os.path.isfile("/etc/ssh/sshd_config"):
        set_permissions("/etc/ssh/sshd_config", 0o600, dry_run=dry_run)

    for p, mode in [
        ("/etc/passwd", 0o644),
        ("/etc/group",  0o644),
        ("/etc/shadow", 0o640),
        ("/etc/gshadow",0o640),
    ]:
        if os.path.exists(p):
            set_permissions(p, mode, dry_run=dry_run)

    if os.path.isfile("/etc/sudoers"):
        set_permissions("/etc/sudoers", 0o440, dry_run=dry_run)
    if os.path.isdir("/etc/sudoers.d"):
        # directorio
        set_permissions("/etc/sudoers.d", 0o750, dry_run=dry_run)
        # ficheros individuales
        for name in os.listdir("/etc/sudoers.d"):
            fp = os.path.join("/etc/sudoers.d", name)
            if os.path.isfile(fp):
                set_permissions(fp, 0o440, dry_run=dry_run)

    # Validar sudoers
    if shutil.which("visudo"):
        if dry_run:
            log("Omitido 'visudo -cf /etc/sudoers' por dry-run.")
        else:
            res = run_cmd(["visudo", "-cf", "/etc/sudoers"], dry_run=dry_run, check=False)
            if res and res.returncode == 0:
                log("sudoers válido.")
            else:
                warn("¡/etc/sudoers tiene errores de sintaxis!")

def harden_ssh(password_auth: str = "keep", dry_run: bool = False) -> None:
    sshd = "/etc/ssh/sshd_config"
    if not os.path.isfile(sshd):
        warn(f"No existe {sshd}; omitiendo cambios SSH.")
        return

    log("Deshabilitando login SSH de root y reforzando opciones…")
    backup = backup_file(sshd, dry_run=dry_run)

    # Reglas base
    edit_sshd_config_key(sshd, "PermitRootLogin", "no", dry_run=dry_run)
    edit_sshd_config_key(sshd, "ChallengeResponseAuthentication", "no", dry_run=dry_run)
    edit_sshd_config_key(sshd, "UsePAM", "yes", dry_run=dry_run)

    # Opcional: PasswordAuthentication
    if password_auth.lower() in ("yes", "no"):
        edit_sshd_config_key(sshd, "PasswordAuthentication", password_auth.lower(), dry_run=dry_run)

    # Validar antes de recargar
    if shutil.which("sshd"):
        if dry_run:
            log("Omitido 'sshd -t' por dry-run.")
        else:
            res = run_cmd(["sshd", "-t"], dry_run=dry_run, check=False)
            if res and res.returncode != 0:
                warn("¡sshd_config inválido! Restaurando backup.")
                if backup and not dry_run:
                    shutil.copy2(backup, sshd)
                return

    # Recargar/reiniciar
    service_reload_or_restart(["sshd", "ssh"], dry_run=dry_run)

def install_configure_fail2ban(bantime: str, findtime: str, maxretry: int, destemail: str, dry_run: bool = False) -> None:
    log("Instalando y configurando Fail2ban…")
    mgr = detect_pkg_mgr()

    if mgr == "apt-get":
        run_cmd(["apt-get", "update", "-y"], dry_run=dry_run, check=False)
        run_cmd(["apt-get", "install", "-y", "fail2ban"], dry_run=dry_run)
    elif mgr == "dnf":
        run_cmd(["dnf", "install", "-y", "fail2ban"], dry_run=dry_run)
    elif mgr == "yum":
        # Intentar EPEL para CentOS/RHEL antiguos
        run_cmd(["yum", "install", "-y", "epel-release"], dry_run=dry_run, check=False)
        run_cmd(["yum", "install", "-y", "fail2ban"], dry_run=dry_run)
    else:
        warn("No se detectó apt/dnf/yum. Instala fail2ban manualmente si lo necesitas.")
        return

    jaild = "/etc/fail2ban"
    jail_local = os.path.join(jaild, "jail.local")
    backup_file(jail_local, dry_run=dry_run)

    cfg = f"""[DEFAULT]
bantime = {bantime}
findtime = {findtime}
maxretry = {maxretry}
destemail = {destemail}
sender = fail2ban@{get_hostname_safe()}
action = %(action_mwl)s

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = systemd
"""
    if dry_run:
        print(f"DRY-RUN: escribir {jail_local} con configuración básica de sshd")
    else:
        os.makedirs(jaild, exist_ok=True)
        with open(jail_local, "w", encoding="utf-8") as f:
            f.write(cfg)

    # Habilitar/arrancar servicio
    if has_systemctl():
        run_cmd(["systemctl", "enable", "fail2ban"], dry_run=dry_run, check=False)
    service_reload_or_restart(["fail2ban"], dry_run=dry_run)

    # Estado
    if shutil.which("fail2ban-client"):
        run_cmd(["fail2ban-client", "status"], dry_run=dry_run, check=False)
        run_cmd(["fail2ban-client", "status", "sshd"], dry_run=dry_run, check=False)

def get_hostname_safe() -> str:
    try:
        res = subprocess.run(["hostname", "-f"], text=True, capture_output=True, check=False)
        name = (res.stdout or "").strip()
        return name or (subprocess.run(["hostname"], text=True, capture_output=True).stdout or "").strip()
    except Exception:
        return "localhost"

# -------------------------
# CLI / main
# -------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Hardening básico para Linux (SSH + permisos + Fail2ban).")
    p.add_argument("--dry-run", action="store_true", help="Simula los cambios sin aplicarlos.")
    p.add_argument("--password-auth", choices=["yes", "no", "keep"], default="keep",
                   help="Forzar PasswordAuthentication en SSH (por defecto: keep => no tocar).")
    p.add_argument("--no-fail2ban", action="store_true", help="No instalar ni configurar Fail2ban.")
    p.add_argument("--bantime", default="1h", help="Duración del ban en Fail2ban (ej: 1h, 3600s).")
    p.add_argument("--findtime", default="10m", help="Ventana para conteo de intentos (ej: 10m).")
    p.add_argument("--maxretry", type=int, default=5, help="Número de intentos fallidos antes del ban.")
    p.add_argument("--destemail", default="root@localhost", help="Correo destino para alertas de Fail2ban.")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    require_root()
    preflight_warnings()
    secure_permissions(dry_run=args.dry_run)
    harden_ssh(password_auth=args.password_auth, dry_run=args.dry_run)
    if not args.no_fail2ban:
        install_configure_fail2ban(
            bantime=args.bantime,
            findtime=args.findtime,
            maxretry=args.maxretry,
            destemail=args.destemail,
            dry_run=args.dry_run,
        )
    log("Listo. Respaldos en /root/hardening-backups. Puedes revisar 'fail2ban-client status sshd'.")

if __name__ == "__main__":
    main()
