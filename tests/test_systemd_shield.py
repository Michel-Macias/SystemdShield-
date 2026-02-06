"""
Unit tests for SystemdShield
"""
import unittest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from models import (
    HardeningOverrides,
    HardeningProfile,
    ProfilesConfig,
    ServiceAnalysis
)
from analyzer import SystemdAnalyzer


class TestHardeningOverrides(unittest.TestCase):
    """Test HardeningOverrides model."""
    
    def test_to_systemd_config(self):
        """Test conversion to systemd config format."""
        overrides = HardeningOverrides(
            NoNewPrivileges="yes",
            PrivateTmp="yes",
            IPAddressDeny="any"
        )
        
        config = overrides.to_systemd_config()
        
        self.assertIn("[Service]", config)
        self.assertIn("NoNewPrivileges=yes", config)
        self.assertIn("PrivateTmp=yes", config)
        self.assertIn("IPAddressDeny=any", config)
    
    def test_none_values_excluded(self):
        """Test that None values are not included in output."""
        overrides = HardeningOverrides(
            NoNewPrivileges="yes",
            PrivateTmp=None  # This should not appear
        )
        
        config = overrides.to_systemd_config()
        
        self.assertIn("NoNewPrivileges=yes", config)
        self.assertNotIn("PrivateTmp", config)


class TestProfilesConfig(unittest.TestCase):
    """Test ProfilesConfig loading."""
    
    def test_load_from_yaml(self):
        """Test loading profiles from YAML file."""
        import yaml
        from models import ProfilesConfig
        
        config_path = Path(__file__).parent.parent / "config" / "profiles.yaml"
        
        with open(config_path) as f:
            data = yaml.safe_load(f)
        
        config = ProfilesConfig(**data)
        
        # Check that profiles are loaded
        self.assertIn("network_service", config.profiles)
        self.assertIn("system_service", config.profiles)
        self.assertIn("critical_service", config.profiles)
        
        # Check service mappings
        self.assertIn("docker.service", config.service_mappings)
        self.assertEqual(config.service_mappings["docker.service"], "virtualization_service")


class TestServiceAnalysis(unittest.TestCase):
    """Test ServiceAnalysis model."""
    
    def test_service_analysis_creation(self):
        """Test creating a ServiceAnalysis."""
        analysis = ServiceAnalysis(
            name="test.service",
            exposure_score=9.6,
            exposure_level="UNSAFE",
            is_active=True,
            is_enabled=True
        )
        
        self.assertEqual(analysis.name, "test.service")
        self.assertEqual(analysis.exposure_score, 9.6)
        self.assertEqual(analysis.exposure_level, "UNSAFE")
        self.assertTrue(analysis.is_active)


class TestSystemdAnalyzer(unittest.TestCase):
    """Test SystemdAnalyzer (integration tests - require systemd)."""
    
    def setUp(self):
        """Set up analyzer."""
        self.analyzer = SystemdAnalyzer()
    
    def test_get_all_services(self):
        """Test getting all services."""
        services = self.analyzer.get_all_services()
        
        # Should return some services
        self.assertGreater(len(services), 0)
        
        # All should end with .service
        for service in services:
            self.assertTrue(service.endswith('.service'))
    
    def test_analyze_service_format(self):
        """Test that analyze_service returns correct format."""
        # Analyze a common service that should exist
        analysis = self.analyzer.analyze_service("systemd-journald.service")
        
        if analysis:  # May be None if service doesn't exist
            self.assertIsNotNone(analysis.name)
            self.assertIsInstance(analysis.is_active, bool)
            self.assertIsInstance(analysis.is_enabled, bool)


class TestHardeningProfiles(unittest.TestCase):
    """Test hardening profile logic."""
    
    def test_network_service_profile(self):
        """Test network service profile doesn't block network."""
        import yaml
        
        config_path = Path(__file__).parent.parent / "config" / "profiles.yaml"
        with open(config_path) as f:
            data = yaml.safe_load(f)
        
        network_profile = data['profiles']['network_service']
        overrides = network_profile['overrides']
        
        # Network services should NOT have IPAddressDeny
        self.assertNotIn('IPAddressDeny', overrides)
        
        # But should have other protections
        self.assertEqual(overrides.get('NoNewPrivileges'), 'yes')
        self.assertEqual(overrides.get('PrivateTmp'), 'yes')
    
    def test_system_service_profile(self):
        """Test system service profile blocks network."""
        import yaml
        
        config_path = Path(__file__).parent.parent / "config" / "profiles.yaml"
        with open(config_path) as f:
            data = yaml.safe_load(f)
        
        system_profile = data['profiles']['system_service']
        overrides = system_profile['overrides']
        
        # System services SHOULD block network
        self.assertEqual(overrides.get('IPAddressDeny'), 'any')
        
        # And have full protections
        self.assertEqual(overrides.get('NoNewPrivileges'), 'yes')
        self.assertEqual(overrides.get('PrivateTmp'), 'yes')
        self.assertEqual(overrides.get('ProtectKernelModules'), 'yes')


if __name__ == '__main__':
    unittest.main()
