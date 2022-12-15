# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import os

from sos.report.plugins import Plugin, RedHatPlugin, UbuntuPlugin


class CephOSD(Plugin, RedHatPlugin, UbuntuPlugin):
    """
    This plugin is for capturing information from Ceph OSD nodes. While the
    majority of this plugin should be version agnotics, several collections are
    dependent upon the version of Ceph installed. Versions that correlate to
    RHCS 4 or RHCS 5 are explicitly handled for differences such as those
    pertaining to log locations on the host filesystem.

    Note that while this plugin will activate based on the presence of Ceph
    containers, commands are run directly on the host as those containers are
    often not configured to successfully run the `ceph` commands collected by
    this plugin. These commands are majorily `ceph daemon` commands that will
    reference discovered admin sockets under /var/run/ceph.
    """

    short_desc = 'CEPH osd'

    plugin_name = 'ceph_osd'
    profiles = ('storage', 'virt', 'container')
    containers = ('ceph-(.*-)?osd.*',)
    files = ('/var/lib/ceph/osd/', '/var/lib/ceph/*/osd*')

    def setup(self):

        self.ceph_version = self.get_ceph_version()

        logdir = '/var/log/ceph'
        libdir = '/var/lib/ceph'
        rundir = '/run/ceph'

        if self.ceph_version >= 16:
            logdir += '/*'
            libdir += '/*'
            rundir += '/*'

        self.add_file_tags({
            f"{logdir}/ceph-(.*-)?osd.*.log": 'ceph_osd_log',
        })

        self.add_forbidden_path([
            "/etc/ceph/*keyring*",
            f"{libdir}/*keyring*",
            f"{libdir}/**/*keyring*",
            # Excludes temporary ceph-osd mount location like
            # /var/lib/ceph/tmp/mnt.XXXX from sos collection.
            f"{libdir}/tmp/*mnt*",
            "/etc/ceph/*bindpass*"
        ])

        # Only collect OSD specific files
        self.add_copy_spec([
            f"{rundir}/ceph-osd*",
            f"{libdir}/**/kv_backend",
            f"{logdir}/ceph-osd*.log",
            f"{logdir}/ceph-volume*.log",
        ])

        self.add_cmd_output([
            "ceph-disk list",
            "ceph-volume lvm list"
        ])

        cmds = [
           "bluestore bluefs available",
           "config diff",
           "config show",
           "dump_blacklist",
           "dump_blocked_ops",
           "dump_historic_ops_by_duration",
           "dump_historic_slow_ops",
           "dump_mempools",
           "dump_ops_in_flight",
           "dump_op_pq_state",
           "dump_osd_network",
           "dump_reservations",
           "dump_watchers",
           "log dump",
           "perf dump",
           "perf histogram dump",
           "objecter_requests",
           "ops",
           "status",
           "version",
        ]

        self.add_cmd_output(
            [f"ceph daemon {i} {c}" for i in self.get_socks() for c in cmds]
        )

    def get_socks(self):
        """
        Find any available admin sockets under /var/run/ceph (or subdirs for
        later versions of Ceph) which can be used for ceph daemon commands
        """
        ceph_sockets = []
        for rdir, dirs, files in os.walk('/var/run/ceph/'):
            for file in files:
                if file.endswith('.asok'):
                    ceph_sockets.append(self.path_join(rdir, file))
        return ceph_sockets

    def get_ceph_version(self):
        ver = self.exec_cmd('ceph --version')
        if ver['status'] == 0:
            try:
                _ver = ver['output'].split()[2]
                return int(_ver.split('.')[0])
            except Exception as err:
                self._log_debug(f"Could not determine ceph version: {err}")
        self._log_error(
            'Failed to find ceph version, command collection will be limited'
        )
        return 0

# vim: set et ts=4 sw=4 :
