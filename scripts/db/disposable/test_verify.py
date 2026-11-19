"""Offline boundary checks for the disposable verifier. No Docker or SQL calls."""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_disposable import engine, guard


class VerificationBoundary(unittest.TestCase):
    def test_remote_and_other_daemons_rejected_before_connect(self):
        for endpoint in ('tcp://127.0.0.1:2375', 'ssh://example.invalid',
                         'unix:///tmp/other.sock', 'npipe:////remote/pipe/docker_engine'):
            with self.subTest(endpoint=endpoint), self.assertRaises(RuntimeError):
                engine(endpoint)

    def test_unknown_dsn_and_connection_overrides_rejected_before_connect(self):
        opener = Mock()
        connect = guard({'migration-token': 'bri_migrator'}, opener)
        for dsn, options in [('migration-token?', {}), ('app-token', {}),
                             ('migration-token', {'hostaddr': '127.0.0.2'}),
                             ('migration-token', {'service': 'other'}),
                             ('migration-token', {'sslmode': 'disable'})]:
            with self.assertRaises(RuntimeError):
                connect(dsn, **options)
        opener.assert_not_called()
        connect('migration-token', connect_timeout=12, autocommit=True)
        opener.assert_called_once_with('bri_migrator', autocommit=True)


if __name__ == '__main__':
    unittest.main()
