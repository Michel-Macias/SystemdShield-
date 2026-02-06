from typing import Dict, List, Optional
from pydantic import BaseModel, Field

# Base de conocimiento pedagógica sobre las directivas de seguridad
DIRECTIVE_EXPLANATIONS = {
    "NoNewPrivileges": "Evita que el servicio y sus hijos ganen nuevos privilegios (ej. mediante binarios setuid). Es fundamental para contener exploits de escalada.",
    "IPAddressDeny": "Restringe el acceso a la red. 'any' bloquea toda comunicación saliente/entrante, reduciendo la superficie de ataque de red.",
    "IPAddressAllow": "Permite el acceso solo a direcciones o rangos específicos, siguiendo el principio de lista blanca.",
    "PrivateTmp": "Asigna un directorio /tmp privado al servicio, invisible para el resto del sistema, evitando ataques de archivos temporales compartidos.",
    "ProtectKernelModules": "Impide que el servicio cargue o descargue módulos del kernel, protegiendo la integridad del núcleo del sistema.",
    "ProtectKernelTunables": "Hace que las variables del kernel (en /proc/sys, /sys) sean de solo lectura, evitando alteraciones en la configuración del núcleo.",
    "ProtectControlGroups": "Impide que el servicio modifique los grupos de control (cgroups), evitando que pueda alterar límites de recursos del sistema.",
    "RestrictRealtime": "Evita que el servicio use planificación de tiempo real, lo que podría usarse para causar ataques de denegación de servicio (DoS).",
    "LockPersonality": "Bloquea la 'personalidad' de ejecución (ej. evita cambios entre 64-bit y 32-bit), dificultando exploits que dependen de cambios de arquitectura.",
    "ProtectHome": "Restringe el acceso a /home, /root y /run/user, protegiendo los datos confidenciales de los usuarios.",
    "ProtectSystem": "Hace que directorios críticos como /usr, /boot y /etc sean de solo lectura para el servicio.",
    "MemoryDenyWriteExecute": "Prohíbe que la memoria sea escribible y ejecutable al mismo tiempo. Crucial para mitigar ataques de inyección de código.",
    "RestrictSUIDSGID": "Impide la creación de archivos con bits SUID/SGID, una vía común para la escalada de privilegios."
}


class HardeningOverrides(BaseModel):
    """Systemd override directives for a hardening profile."""
    NoNewPrivileges: Optional[str] = None
    IPAddressDeny: Optional[str] = None
    IPAddressAllow: Optional[str] = None
    PrivateTmp: Optional[str] = None
    ProtectKernelModules: Optional[str] = None
    ProtectKernelTunables: Optional[str] = None
    ProtectControlGroups: Optional[str] = None
    RestrictRealtime: Optional[str] = None
    LockPersonality: Optional[str] = None
    ProtectHome: Optional[str] = None
    ProtectSystem: Optional[str] = None
    MemoryDenyWriteExecute: Optional[str] = None
    RestrictSUIDSGID: Optional[str] = None
    
    def to_systemd_config(self) -> str:
        """Convert to systemd unit file format."""
        lines = ["[Service]"]
        for field, value in self.model_dump(exclude_none=True).items():
            lines.append(f"{field}={value}")
        return "\n".join(lines)

    def get_explanations(self) -> Dict[str, str]:
        """Get educational explanations for applied directives."""
        applied = self.model_dump(exclude_none=True)
        return {field: DIRECTIVE_EXPLANATIONS.get(field, "Sin descripción disponible.") for field in applied}


class HardeningProfile(BaseModel):
    """A hardening profile with description and overrides."""
    description: str
    overrides: HardeningOverrides


class ProfilesConfig(BaseModel):
    """Complete profiles configuration from YAML."""
    profiles: Dict[str, HardeningProfile]
    service_mappings: Dict[str, str] = Field(default_factory=dict)


class ExclusionsConfig(BaseModel):
    """Services excluded from automatic hardening."""
    excluded_services: List[str]
    exclusion_reasons: Optional[Dict[str, str]] = None


class ServiceAnalysis(BaseModel):
    """Analysis result for a single service."""
    name: str
    exposure_score: Optional[float] = None
    exposure_level: Optional[str] = None  # UNSAFE, EXPOSED, MEDIUM, OK
    is_active: bool = False
    is_enabled: bool = False
    suggested_profile: Optional[str] = None


class HardeningResult(BaseModel):
    """Result of applying hardening to a service."""
    service_name: str
    success: bool
    profile_applied: Optional[str] = None
    previous_score: Optional[float] = None
    new_score: Optional[float] = None
    rollback_performed: bool = False
    error: Optional[str] = None
