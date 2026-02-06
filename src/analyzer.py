"""
SystemdAnalyzer: Wrapper for systemd-analyze security.
"""
import subprocess
import re
from typing import List, Optional
from models import ServiceAnalysis


class SystemdAnalyzer:
    """Analyzes systemd services using systemd-analyze."""
    
    def get_all_services(self) -> List[str]:
        """Get list of all systemd services."""
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
                capture_output=True,
                text=True,
                check=True
            )
            services = []
            for line in result.stdout.splitlines():
                # Extract service name from systemctl output
                parts = line.split()
                if parts and parts[0].endswith('.service'):
                    services.append(parts[0])
            return services
        except subprocess.CalledProcessError as e:
            print(f"Error listing services: {e}")
            return []
    
    def analyze_service(self, service_name: str) -> Optional[ServiceAnalysis]:
        """
        Analyze security of a specific service.
        Returns ServiceAnalysis or None if analysis fails.
        """
        try:
            # Get security analysis
            result = subprocess.run(
                ["systemd-analyze", "security", service_name, "--no-pager"],
                capture_output=True,
                text=True,
                check=False  # Don't raise on non-zero exit
            )
            
            # Parse exposure level from output
           # Last line format: "→ Overall exposure level for X: 9.6 UNSAFE 😨"
            exposure_match = re.search(
                r'Overall exposure level.*?:\s+([\d.]+)\s+(\w+)',
                result.stdout
            )
            
            exposure_score = None
            exposure_level = None
            if exposure_match:
                exposure_score = float(exposure_match.group(1))
                exposure_level = exposure_match.group(2)
            
            # Get service status
            status_result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True,
                check=False
            )
            is_active = status_result.stdout.strip() == "active"
            
            # Get enabled status
            enabled_result = subprocess.run(
                ["systemctl", "is-enabled", service_name],
                capture_output=True,
                text=True,
                check=False
            )
            is_enabled = enabled_result.stdout.strip() in ["enabled", "static"]
            
            return ServiceAnalysis(
                name=service_name,
                exposure_score=exposure_score,
                exposure_level=exposure_level,
                is_active=is_active,
                is_enabled=is_enabled
            )
            
        except Exception as e:
            print(f"Error analyzing {service_name}: {e}")
            return None
    
    def get_high_exposure_services(self, threshold: float = 8.0) -> List[ServiceAnalysis]:
        """Get all services with exposure score above threshold."""
        services = self.get_all_services()
        high_exposure = []
        
        for service in services:
            analysis = self.analyze_service(service)
            if analysis and analysis.exposure_score and analysis.exposure_score >= threshold:
                high_exposure.append(analysis)
        
        return sorted(high_exposure, key=lambda x: x.exposure_score or 0, reverse=True)
