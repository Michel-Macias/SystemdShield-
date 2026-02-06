# SystemdShield 🛡️

**Automated Systemd Service Hardening Tool**

## Descripción

SystemdShield automatiza el proceso de hardening de servicios systemd aplicando perfiles de seguridad predefinidos basados en las mejores prácticas de "Privilegio Mínimo" y "Defensa en Profundidad".

Desarrollado tras analizar y endurecer manualmente más de 35 servicios en un sistema Ubuntu 24.04 LTS, esta herramienta encapsula todo ese conocimiento en perfiles reutilizables y seguros.

## Características

- **Análisis Automático**: Detecta servicios con alta exposición usando `systemd-analyze security`
- **Perfiles Inteligentes**: Aplica configuraciones específicas según el tipo de servicio:
  - `network_service` - Servicios que requieren acceso a red
  - `system_service` - Servicios internos sin requisitos de red
  - `critical_service` - Hardening quirúrgico para servicios críticos (gdm, dbus)
  - `monitoring_service` - Para herramientas de monitorización (glances)
  - `virtualization_service` - Docker, libvirtd, VirtualBox
- **Modo Educativo**: Informes detallados que explican qué técnica de ataque previene cada directiva aplicada, ideal para aprendizaje técnico.
- **Rollback Seguro**: Revierte cambios automáticamente si el servicio falla tras el hardening
- **No Invasivo**: Usa overrides de systemd sin modificar los archivos originales del sistema
- **Lista de Exclusiones**: Protege servicios críticos como `user@1000.service` de hardening accidental

## Instalación

```bash
# Clonar o copiar el proyecto
cd /path/to/systemd_shield

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

## Uso

### 1. Auditar el Sistema

Muestra todos los servicios con alta exposición:

```bash
venv/bin/python3 src/main.py audit

# Ver solo servicios con score >= 9.5
venv/bin/python3 src/main.py audit --threshold 9.5

# Ver TODOS los servicios (incluso los seguros)
venv/bin/python3 src/main.py audit --all
```

**Salida esperada:**
```
🔍 SystemdShield Security Audit

┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Service                ┃ Score ┃ Level  ┃ Status      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━┩
│ clamav-daemon.service  │   9.6 │ UNSAFE │ 🟢 Active   │
│ docker.service         │   9.6 │ UNSAFE │ 🟢 Active   │
└────────────────────────┴───────┴────────┴─────────────┘
```

### 2. Endurecer un Servicio Individual

```bash
# Modo dry-run (mostrar sin aplicar)
sudo venv/bin/python3 src/main.py harden clamav-daemon.service --dry-run

# Aplicar hardening real
sudo venv/bin/python3 src/main.py harden clamav-daemon.service

# Forzar un perfil específico
sudo venv/bin/python3 src/main.py harden docker.service --profile virtualization_service
```

**Salida esperada:**
```
🛡️  Hardening clamav-daemon.service

✅ Successfully hardened clamav-daemon.service (9.6 → 8.0)
Profile applied: system_service
```

### 3. Hardening Masivo (Batch Mode)

Endurece automáticamente todos los servicios con exposición alta:

```bash
# Dry-run primero (recomendado)
sudo venv/bin/python3 src/main.py harden --batch --dry-run --threshold 9.0

# Aplicar a todos los servicios con score >= 9.0
sudo venv/bin/python3 src/main.py harden --batch --threshold 9.0
```

### 4. Revertir Cambios

Si algo sale mal o quieres deshacer el hardening:

```bash
sudo venv/bin/python3 src/main.py revert clamav-daemon.service
```

## Arquitectura

```
systemd_shield/
├── config/
│   ├── profiles.yaml         # Definición de perfiles de hardening
│   └── exclusions.yaml       # Servicios excluidos (user@1000, emergency, etc.)
├── src/
│   ├── analyzer.py           # Wrapper para systemd-analyze security
│   ├── models.py             # Modelos Pydantic para validación
│   ├── hardening.py          # Motor de aplicación y rollback
│   └── main.py               # CLI con Typer
└── tests/                    # Tests unitarios
```

### Flujo de Hardening

1. **Análisis**: Se ejecuta `systemd-analyze security` para obtener el score inicial
2. **Selección de Perfil**: Se mapea el servicio a un perfil (automático o manual)
3. **Creación de Override**: Se genera `/etc/systemd/system/<service>.d/override.conf`
4. **Recarga**: `systemctl daemon-reload`
5. **Restart**: Se reinicia el servicio (solo si estaba activo)
6. **Health Check**: Se verifica que el servicio siga `active`
7. **Rollback Automático**: Si falla, se revierte el override y se restaura el estado anterior

## Perfiles de Hardening

### `system_service`
Para servicios que NO requieren red:
- `NoNewPrivileges=yes` - Evita escalada de privilegios
- `IPAddressDeny=any` - Bloquea acceso a red
- `PrivateTmp=yes` - Aislamiento de `/tmp`
- `ProtectKernelModules=yes` - No puede cargar módulos del kernel
- ...y más directivas de protección

### `network_service`
Para servicios que SÍ requieren red:
- Similar a `system_service` pero **sin** `IPAddressDeny`

### `critical_service`
Para servicios críticos del sistema (gdm, dbus):
- Hardening quirúrgico y conservador
- Omite directives que podrían romper funcionalidad

### `virtualization_service`
Para Docker, libvirtd, VirtualBox:
- Permite `ProtectControlGroups=no` (necesario para gestión de contenedores)
- Omite `ProtectKernelModules` (VirtualBox puede necesitarlo)

## Servicios Excluidos

Los siguientes servicios **nunca** se endurecen automáticamente:
- `user@1000.service` - Gestor de sesión de usuario (rompe escritorio)
- `emergency.service` - Modo de recuperación
- `systemd-logind.service` - Gestión de login

Puedes editarlos en `config/exclusions.yaml`.

## Seguridad

Este proyecto se rige por el principio de **"Security by Design"**:

- **No destructivo**: Todos los cambios se aplican como overrides, los archivos originales permanecen intactos
- **Reversible**: Cualquier cambio puede deshacerse con `systemctl revert <service>` o usando el comando `revert`
- **Safe by default**: Si un servicio falla tras el hardening, se revierte automáticamente
- **Idempotente**: Ejecutar el hardening varias veces produce el mismo resultado

## Testing

Para asegurar que los cambios no rompan el sistema:

1. **Siempre usar dry-run primero**: `--dry-run`
2. **Probar en un servicio no crítico**: Ej. `clamav-daemon.service`
3. **Verificar logs**: `journalctl -u <service> -n 50`
4. **Comprobar estado**: `systemctl status <service>`

## Ejemplos Reales

### Caso de Uso 1: Endurecer ClamAV
```bash
$ sudo venv/bin/python3 src/main.py harden clamav-daemon.service
✅ Successfully hardened clamav-daemon.service (9.6 → 8.0)
```

### Caso de Uso 2: Batch Hardening de Servicios Inactivos
```bash
$ sudo venv/bin/python3 src/main.py audit --threshold 9.5 | grep "Inactive"
│ apport-autoreport.service  │   9.6 │ UNSAFE │ ⚫ Inactive  │

$ sudo venv/bin/python3 src/main.py harden apport-autoreport.service
✅ Successfully hardened apport-autoreport.service (9.6 → 7.8)
```

## Contribuir

Si encuentras un servicio que se rompe con algún perfil, puedes:
1. Añadirlo a `config/exclusions.yaml`
2. Crear un perfil específico para ese tipo de servicio en `config/profiles.yaml`
3. Mapear el servicio al perfil en `service_mappings`

## Licencia

MIT License - Creado para el proyecto de hardening de AcerManteniniento

## Créditos

Desarrollado tras más de 50 horas de hardening manual documentado en `task_servicios_systemd.md`.
Basado en las mejores prácticas de systemd security y las recomendaciones de Lynis.
