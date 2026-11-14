from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from bri.api.app import ApiSettings
from bri.api.server import resolve_server_bind


class ServerBindTests(unittest.TestCase):
    def test_development_bind_is_loopback_and_uses_configured_port(self) -> None:
        self.assertEqual(
            resolve_server_bind({"BRI_ENVIRONMENT": "development", "PORT": "8123"}),
            ("127.0.0.1", 8123),
        )

    def test_hosted_development_binds_all_interfaces_and_honours_platform_port(self) -> None:
        self.assertEqual(
            resolve_server_bind({"BRI_ENVIRONMENT": "hosted-development", "PORT": "8080"}),
            ("0.0.0.0", 8080),
        )

    def test_invalid_environment_and_ports_are_rejected(self) -> None:
        for env in (
            {"BRI_ENVIRONMENT": "production", "PORT": "8000"},
            {"BRI_ENVIRONMENT": "hosted-development", "PORT": "0"},
            {"BRI_ENVIRONMENT": "development", "PORT": "65536"},
            {"BRI_ENVIRONMENT": "development", "PORT": "not-a-port"},
        ):
            with self.subTest(env=env), self.assertRaises(ValueError):
                resolve_server_bind(env)


class HostedEnvironmentTests(unittest.TestCase):
    def test_hosted_mode_never_loads_the_repository_local_dotenv_file(self) -> None:
        environment = {
            "BRI_ENVIRONMENT": "hosted-development",
            "BRI_AUTH_MODE": "supabase",
            "BRI_DEV_AUTH_ENABLED": "false",
            "SUPABASE_URL": "https://bwqdyibvuecgthtatrtv.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "sb_publishable_unit_test",
        }
        with patch.dict(os.environ, environment, clear=True), patch("bri.api.app.load_dotenv") as load_dotenv:
            settings = ApiSettings.from_environment()
        self.assertEqual(settings.environment, "hosted-development")
        load_dotenv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
