# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from sos.policies.distros import LinuxPolicy
from sos.policies.init_systems import InitSystem
from sos.report.plugins.doca_dpf import DocaDpf


class MockOptions:
    all_logs = False
    dry_run = False
    since = None
    log_size = 25
    allow_system_changes = False
    no_postproc = False
    skip_files = []
    skip_commands = []
    sysroot = None


class GatePlugin(DocaDpf):
    """DocaDpf with the injected admin.conf path still listed."""

    files = ('/etc/kubernetes/admin.conf',)

    def __init__(self, commons):
        self.path_checks = []
        super().__init__(commons)

    def path_exists(self, path):
        self.path_checks.append(path)
        return True


class DocaDpfMasterGateTests(unittest.TestCase):

    def setUp(self):
        self._saved_env = os.environ.get('SOS_COLLECT_CLUSTER')
        os.environ.pop('SOS_COLLECT_CLUSTER', None)
        self.plugin = GatePlugin({
            'sysroot': os.getcwd(),
            'policy': LinuxPolicy(init=InitSystem(), probe_runtime=False),
            'cmdlineopts': MockOptions(),
            'devices': {}
        })

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop('SOS_COLLECT_CLUSTER', None)
        else:
            os.environ['SOS_COLLECT_CLUSTER'] = self._saved_env

    def test_admin_conf_does_not_imply_master(self):
        self.plugin.path_checks = []
        self.assertIn('/etc/kubernetes/admin.conf', self.plugin.files)
        self.assertFalse(self.plugin.check_is_master())
        self.assertEqual(self.plugin.path_checks, [])

    def test_only_exact_env_enables_master(self):
        for value in ('', '0', 'true', 'yes'):
            os.environ['SOS_COLLECT_CLUSTER'] = value
            self.assertFalse(self.plugin.check_is_master())
        os.environ['SOS_COLLECT_CLUSTER'] = '1'
        self.assertTrue(self.plugin.check_is_master())

    def test_setup_skips_cluster_dump_without_env(self):
        self.plugin.collect_per_resource_details = MagicMock()
        self.plugin._collect_all_dpu_clusters = MagicMock()
        self.plugin.setup()
        self.plugin.collect_per_resource_details.assert_not_called()
        self.plugin._collect_all_dpu_clusters.assert_not_called()

    def test_setup_collects_cluster_when_env_set(self):
        os.environ['SOS_COLLECT_CLUSTER'] = '1'
        self.plugin.collect_per_resource_details = MagicMock()
        self.plugin._collect_all_dpu_clusters = MagicMock()
        self.plugin.setup()
        self.plugin.collect_per_resource_details.assert_called_once()
        self.plugin._collect_all_dpu_clusters.assert_called_once()

    def test_discover_parses_kubectl_json_from_file(self):
        payload = {
            'items': [
                {
                    'metadata': {'name': 'dpu-1', 'namespace': 'dpf'},
                    'spec': {'kubeconfig': 'dpu-1-admin'}
                },
                {
                    'metadata': {'name': 'skip-me', 'namespace': 'dpf'},
                    'spec': {}
                }
            ]
        }
        with tempfile.NamedTemporaryFile(
                'w', encoding='utf-8', delete=False) as fh:
            json.dump(payload, fh)
            json_path = fh.name
        self.addCleanup(os.remove, json_path)

        self.plugin._collect_cmd_output = MagicMock(return_value={
            'status': 0,
            'output': json.dumps(payload),
            'filename': json_path,
        })
        clusters = self.plugin._discover_dpu_clusters()

        args, kwargs = self.plugin._collect_cmd_output.call_args
        self.assertIn('get dpucluster -A -o json', args[0])
        self.assertEqual(kwargs['suggest_filename'], 'dpucluster-list.json')
        self.assertEqual(kwargs['subdir'], 'cluster-info')
        self.assertTrue(kwargs['to_file'])
        self.assertEqual(clusters, [{
            'name': 'dpu-1',
            'namespace': 'dpf',
            'kubeconfig': 'dpu-1-admin',
        }])

    def test_discover_nonzero_status_skips_parse(self):
        self.plugin._collect_cmd_output = MagicMock(return_value={
            'status': 1,
            'output': 'boom',
            'filename': '',
        })
        self.assertEqual(self.plugin._discover_dpu_clusters(), [])

    def test_discover_missing_file(self):
        self.plugin._collect_cmd_output = MagicMock(return_value={
            'status': 0,
            'output': '',
            'filename': '/no/such/dpucluster-list.json',
        })
        self.assertEqual(self.plugin._discover_dpu_clusters(), [])

    def test_discover_invalid_json(self):
        with tempfile.NamedTemporaryFile(
                'w', encoding='utf-8', delete=False) as fh:
            fh.write('not-json')
            json_path = fh.name
        self.addCleanup(os.remove, json_path)
        self.plugin._collect_cmd_output = MagicMock(return_value={
            'status': 0,
            'output': '',
            'filename': json_path,
        })
        self.assertEqual(self.plugin._discover_dpu_clusters(), [])

    def test_report_sh_single_thread_keeps_output_dir(self):
        root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '..', '..'))
        script = os.path.join(root, 'scripts', 'report.sh')
        with open(script, encoding='utf-8') as fh:
            text = fh.read()
        self.assertIn('options+=("-t" "1")', text)
        self.assertIn(': "${OUTPUT_DIR:=/host/tmp}"', text)


if __name__ == '__main__':
    unittest.main()
