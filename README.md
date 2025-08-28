# Linux Hardening Script (Python y Bash)

Script de hardening básico para servidores Linux que automatiza tareas esenciales:

- Ajuste de permisos en archivos sensibles (`/etc/{passwd,group,shadow,gshadow}`, `sudoers`, `sshd_config`, `/root`).
- Deshabilita el login SSH de root y refuerza opciones seguras (idempotente).
- Instala y configura Fail2ban con una jail para `sshd` (parámetros ajustables).

> Este repo incluye **`hardening.py` y **`hardening.sh`** como implementación principal.

---

## Sistemas soportados

- Debian/Ubuntu y derivados (usa `apt-get`)
- RHEL/CentOS/Alma/Rocky (usa `dnf` o `yum`; intenta EPEL si aplica)
- Requiere `openssh-server` instalado para aplicar cambios en SSH.

---

## Requisitos

- Ejecutar como root (o `sudo`).
- Conectividad a internet para instalar paquetes (Fail2ban).
- Recomendado: tener al menos un usuario no-root con sudo antes de deshabilitar el acceso SSH de root:
  ```bash
  adduser <usuario>
  usermod -aG sudo <usuario>     # Debian/Ubuntu
  usermod -aG wheel <usuario>    # RHEL/CentOS
