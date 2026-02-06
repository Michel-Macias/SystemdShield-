"""
HardeningEngine: Applies and rolls back systemd overrides safely.
"""
import subprocess
import shutil
from pathlib import Path
from typing import Optional
import yaml

from models import (
    HardeningProfile,
    HardeningResult,
    ProfilesConfig,
    ExclusionsConfig
)
from analyzer import SystemdAnalyzer


class HardeningEngine:
    """Manages application and rollback of systemd service hardening."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.profiles = self._load_profiles()
        self.exclusions = self._load_exclusions()
        self.analyzer = SystemdAnalyzer()
        self.override_base = Path("/etc/systemd/system")
    
    def _load_profiles(self) -> ProfilesConfig:
        """Load hardening profiles from YAML."""
        profiles_file = self.config_dir / "profiles.yaml"
        with open(profiles_file) as f:
            data = yaml.safe_load(f)
        return ProfilesConfig(**data)
    
    def _load_exclusions(self) -> ExclusionsConfig:
        """Load exclusion list from YAML."""
        exclusions_file = self.config_dir / "exclusions.yaml"
        with open(exclusions_file) as f:
            data = yaml.safe_load(f)
        return ExclusionsConfig(**data)
    
    def is_excluded(self, service_name: str) -> bool:
        """Check if a service is in the exclusion list."""
        for pattern in self.exclusions.excluded_services:
            if pattern.endswith('*') and service_name.startswith(pattern[:-1]):
                return True
            if service_name == pattern:
                return True
        return False
    
    def get_profile_for_service(self, service_name: str) -> Optional[str]:
        """Get the recommended profile for a service."""
        # Check explicit mapping first
        if service_name in self.profiles.service_mappings:
            return self.profiles.service_mappings[service_name]
        
        # Default heuristics based on service name
        if any(x in service_name for x in ['network', 'wpa', 'dhcp']):
            return "network_service"
        if any(x in service_name for x in ['docker', 'libvirt', 'virtual']):
            return "virtualization_service"
        if any(x in service_name for x in ['dbus', 'gdm', 'login']):
            return "critical_service"
        
        # Default to system_service
        return "system_service"
    
    def apply_hardening(
        self,
        service_name: str,
        profile_name: Optional[str] = None,
        dry_run: bool = False
    ) -> HardeningResult:
        """
        Apply hardening to a service.
        
        Args:
            service_name: Name of the service to harden
            profile_name: Profile to apply (auto-detected if None)
            dry_run: If True, only show what would be done
        
        Returns:
            HardeningResult with success status and details
        """
        # Check exclusions
        if self.is_excluded(service_name):
            return HardeningResult(
                service_name=service_name,
                success=False,
                error="Service is in exclusion list"
            )
        
        # Get initial score
        initial_analysis = self.analyzer.analyze_service(service_name)
        if not initial_analysis:
            return HardeningResult(
                service_name=service_name,
                success=False,
                error="Failed to analyze service"
            )
        
        previous_score = initial_analysis.exposure_score
        
        # Determine profile
        if not profile_name:
            profile_name = self.get_profile_for_service(service_name)
        
        if profile_name not in self.profiles.profiles:
            return HardeningResult(
                service_name=service_name,
                success=False,
                error=f"Unknown profile: {profile_name}"
            )
        
        profile = self.profiles.profiles[profile_name]
        
        if dry_run:
            print(f"\n[DRY RUN] Would apply profile '{profile_name}' to {service_name}")
            print(profile.overrides.to_systemd_config())
            return HardeningResult(
                service_name=service_name,
                success=True,
                profile_applied=profile_name,
                previous_score=previous_score
            )
        
        # Create override directory
        override_dir = self.override_base / f"{service_name}.d"
        override_file = override_dir / "override.conf"
        backup_file = override_dir / "override.conf.backup"
        
        try:
            # Backup existing override if present
            if override_file.exists():
                shutil.copy2(override_file, backup_file)
            
            # Create directory
            override_dir.mkdir(parents=True, exist_ok=True)
            
            # Write override
            with open(override_file, 'w') as f:
                f.write(f"# Generated by SystemdShield - Profile: {profile_name}\n")
                f.write(profile.overrides.to_systemd_config())
            
            # Reload daemon
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            
            # Restart service if it was active
            if initial_analysis.is_active:
                subprocess.run(
                    ["systemctl", "restart", service_name],
                    check=True,
                    timeout=10
                )
                
                # Verify it's still active
                status = subprocess.run(
                    ["systemctl", "is-active", service_name],
                    capture_output=True,
                    text=True
                )
                
                if status.stdout.strip() != "active":
                    # Rollback!
                    print(f"⚠️  Service {service_name} failed to restart. Rolling back...")
                    self.rollback(service_name, backup_file)
                    return HardeningResult(
                        service_name=service_name,
                        success=False,
                        profile_applied=profile_name,
                        previous_score=previous_score,
                        rollback_performed=True,
                        error="Service failed health check after hardening"
                    )
            
            # Get new score
            new_analysis = self.analyzer.analyze_service(service_name)
            new_score = new_analysis.exposure_score if new_analysis else None
            
            return HardeningResult(
                service_name=service_name,
                success=True,
                profile_applied=profile_name,
                previous_score=previous_score,
                new_score=new_score
            )
            
        except Exception as e:
            # Rollback on any error
            self.rollback(service_name, backup_file)
            return HardeningResult(
                service_name=service_name,
                success=False,
                profile_applied=profile_name,
                previous_score=previous_score,
                rollback_performed=True,
                error=str(e)
            )
    
    def rollback(self, service_name: str, backup_file: Optional[Path] = None):
        """Rollback hardening changes for a service."""
        override_dir = self.override_base / f"{service_name}.d"
        override_file = override_dir / "override.conf"
        
        try:
            if backup_file and backup_file.exists():
                # Restore backup
                shutil.copy2(backup_file, override_file)
            elif override_file.exists():
                # Remove override
                override_file.unlink()
            
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "restart", service_name], check=False)
            print(f"✅ Rolled back {service_name}")
        except Exception as e:
            print(f"❌ Error during rollback of {service_name}: {e}")
