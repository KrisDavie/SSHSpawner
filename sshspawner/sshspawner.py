###############################################################################
# Copyright (c) 2018, Lawrence Livermore National Security, LLC
# Produced at the Lawrence Livermore National Laboratory
# Written by Thomas Mendoza mendoza33@llnl.gov
# LLNL-CODE-771750
# All rights reserved
#
# This file is part of SSHSpawner: https://github.com/LLNL/SSHSpawner
#
# SPDX-License-Identifier: BSD-3-Clause
###############################################################################

import os
import pipes
import pwd
import re
import stat
import pexpect
import shutil
import signal
import psutil
from glob import glob
from urllib.parse import urlparse, urlunparse
from pexpect import popen_spawn
from tempfile import TemporaryDirectory
from jupyterhub.spawner import LocalProcessSpawner
from traitlets import default
from traitlets import Bool, Integer, Unicode, Int, List, Dict
from jupyterhub.utils import (
    wait_for_http_server,
    make_ssl_context,
)

_script_template = """#!/bin/bash
# entrypoint for shared kernel link?
# start the notebook with appropriate args
{}
"""


class HostNotFound(Exception):
    def __init__(self, host):
        super().__init__(self, f"Unable to locate host {host}.")


class ConnectionError(Exception):
    def __init__(self, host):
        super().__init__(self, f"Unable to connect to host {host}")


class SSHSpawner(LocalProcessSpawner):
    ssh_target = ""

    resource_path = Unicode(
        ".jupyter/jupyterhub/resources",
        help="""The base path where all necessary resources are placed.
        Generally left relative so that resources are placed into this base
        directory in the users home directory.
        """,
    ).tag(config=True)

    hostname = Unicode(
        "", help="Hostname of the hub host. Useful if the Hub is in a container."
    ).tag(config=True)

    known_hosts = Unicode(
        "",
        help="Premade known_hosts file to enable trusted, seamless ssh.",
    ).tag(config=True)

    ssh_hosts = List([], help="List of available hosts to ssh to.").tag(config=True)

    allow_origin_pattern = Unicode(
        "", help="Pattern for CORS requests (when behind a reverse proxy)"
    ).tag(config=True)

    local_logfile = Unicode(
        "",
        help="""Name of the file to redirect stdout and stderr from the remote
        notebook.""",
    ).tag(config=True)

    ssh_control_persist_time = Int(
        1,
        help="""The amount of time for SSH connections over the control master
        will stay active""",
    ).tag(config=True)

    cleanup_server = Bool(
        True, help="Teardown the notebook server when contact is lost with the hub."
    ).tag(config=True)

    hub_check_interval = Integer(
        5, help="Interval in minutes to check if notebook has been orphaned."
    ).tag(config=True)

    notebook_max_lifetime = Integer(
        12, help="Max lifetime in hours for a remotely spawned notebook to live."
    ).tag(config=True)

    idle_timeout = Integer(
        300, help="""The amount of time before culling an idle kernel."""
    ).tag(config=True)

    start_notebook_cmd = Unicode(
        "start-notebook", help="""The command to run to start a notebook"""
    ).tag(config=True)

    stop_notebook_cmd = Unicode(
        "stop-notebook", help="""The command to run to stop a running notebook"""
    ).tag(config=True)

    ssh_host_prefix = Unicode(
        "",
        help="""A prefix added to hosts in ssh configs. Typically used to prevent 
        interaction between user and system ssh settings.""",
    ).tag(config=True)

    get_port_remote_location = Dict(
        Unicode(),
        help="""Dict. Keys are hosts as defined in `ssh_hosts`, 
        values are paths to remote paths to the get_port script""",
    ).tag(config=True)

    cmd = Dict(
        key_trait=Unicode(),
        value_trait=List(),
        help="""Dict. Keys are hosts as defined in `ssh_hosts`, values are commands 
        to run a jupyterhub-singleuser instance""",
    ).tag(config=True)

    conda_env_loc = Dict(
        Unicode(),
        help="""Dict. Keys are hosts as defined in `ssh_hosts`, values are paths 
        to a conda env on the corresponding remote server.""",
    ).tag(config=True)

    conda_env_name = Dict(
        Unicode(),
        help="""Dict. Keys are hosts as defined in `ssh_hosts`, values are the name 
        for a specific environment in the conda env on the corresponding remote server.""",
    ).tag(config=True)

    remote_notebook_env = Dict(
        Unicode(),
        help="""Dict. Keys are hosts as defined in `ssh_hosts`, values are an 
        environment variable containing remote location for notebooks.""",
    ).tag(config=True)

    remote_notebook_folder = Unicode(
        "",
        help="Folder to contain remote notebooks.",
    ).tag(config=True)

    pre_server_startup_script = Dict(
        Unicode(),
        help="""Dict. Keys are hosts as defined in `ssh_hosts`, values are strings 
        containing a bash snippet to run beore launching the single-user server.""",
    ).tag(config=True)

    lab_enabled = Bool(True, help="Using jupyterlab?").tag(config=True)

    _stopping = False
    _started = False

    def load_state(self, state):
        """Restore state about spawned single-user server after a hub restart.

        Local processes only need the process id.
        """
        super(SSHSpawner, self).load_state(state)
        if state == {}:
            return

        self.pid = state.get("pid", 0)
        self.ssh_target = state.get("ssh_target", "")
        self.port = state.get("port", "")
        cmd = self.cmd[self.ssh_target]

        proc_found = False

        if self.pid == 0:
            self.log.debug("Stored PID is 0")

        for p in psutil.process_iter():
            if (
                f"{self.port}:127.0.0.1:{self.port}" in p.cmdline()
                and p.username() == self.user.name
            ):
                self.log.debug(
                    f"Found existing tunnel with correct port ({self.port}) and user ({self.user.name})"
                )
                proc_found = True
                if p.pid != self.pid and self.pid > 0:
                    self.log.warning(
                        "PID of found process is NOT the same as... updating"
                    )
                    self.pid = p.pid
                break

        if not proc_found:
            self.log.info(
                f"Tunnel was not found. Opening new tunnel on port: {self.port} to {self.ssh_target} for {self.user.name}"
            )
            opts = self.ssh_opts(
                persist=self.ssh_control_persist_time, known_hosts=self.known_hosts
            )

            check_server_exists = self.spawn_as_user(
                f"ssh {opts} {self.ssh_target} \"ps x | grep '{cmd[0]} --port={self.port}' | wc -l\" 2>/dev/null",
                timeout=None,
            )

            check_server_exists.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=15)
            self.log.debug(check_server_exists.before)
            try:
            if int(check_server_exists.before.split()[-1]) <= 2:
                self.log.error(
                    f"Existing server on host {self.ssh_target}:{self.port} does not exist remotely for user {self.user.name}!"
                )
            else:
                self._started = True

                self.resource_path = os.path.join(self.resource_path, self.ssh_target)

                start_tunnel_child = self.spawn_as_user(
                    f"ssh {opts} -L {self.port}:127.0.0.1:{self.port} {self.ssh_target}",
                    timeout=None,
                )
                self.proc = start_tunnel_child.proc
                self.pid = self.proc.pid
            except ValueError as e:
                self.log.error(
                    f"""Could not determine if server exists. ps x output: 
                    {check_server_exists.before}
                    Error: {e}
                    """
                )



    def get_state(self):
        """Save state that is needed to restore this spawner instance after a hub restore.

        Local processes only need the process id.
        """
        state = super(SSHSpawner, self).get_state()
        if self.pid:
            state["pid"] = self.pid
        if self.ssh_target:
            state["ssh_target"] = self.ssh_target
        if self.port:
            state["port"] = self.port

        return state

    def clear_state(self):
        """clear any state (called after shutdown)"""
        super().clear_state()
        self.pid = 0
        self.ssh_target = ""
        self.port = 0

    @property
    def ssh_socket(self):
        return f"/tmp/sshspawner-{self.user.name}@{self.ssh_target}"

    def get_user_ssh_hosts(self):
        return self.ssh_hosts

    @default("options_form")
    def _options_form(self):
        """Populate a list of ssh targets on the pre_spawn form"""

        hosts = self.get_user_ssh_hosts()
        if not hosts:
            return """
            <label for="host">Input host for notebook launch:</label>
            <input type="text" name="host" class="form-control">
            """
        if self.ssh_host_prefix:
            options = "".join(
                [
                    f'<option value="{host}">{host[len(self.ssh_host_prefix):]}</option>'
                    for host in hosts
                ]
            )
        else:
            options = "".join(
                [f'<option value="{host}">{host}</option>' for host in hosts]
            )
        return f"""
        <label for="host">Select host for notebook launch:</label>
        <select name="host" class="form-control">{options}</select>
        """

    def options_from_form(self, formdata):
        """Turn html formdata from `options_form` into a dict for later use"""

        options = {}
        options["host"] = pipes.quote(formdata.get("host", [""])[0].strip())
        return options

    def ssh_opts(self, persist=180, known_hosts="", batch_mode=True, other_opts=None):
        """Default set of options to attach to ssh commands

        The minimum arguments are a good, known_hosts file and enabling
        batch mode. The known_hosts file avoids user's known_hosts files
        which may not trust other hosts. Batch mode will cause ssh to fail
        on prompting for a password.

        This implementation also uses ssh ControlMaster to speed up and
        simplify repeated operations over SSH.
        """

        opts = {
            "ControlMaster": "auto",
            "ControlPath": "/tmp/sshspawner-%u@%n",
            "ControlPersist": persist,
            "BatchMode": batch_mode,
        }

        if known_hosts:
            opts["UserKnownHostsFile"] = known_hosts
        else:
            self.log.warning("Skipping host key check")
            opts["StrictHostKeyChecking"] = "no"

        if other_opts:
            opts.extend(other_opts)

        return f"-T " + " ".join([f"-o {opt}={val}" for opt, val in opts.items()])

    def spawn_as_user(self, cmd, timeout=10):
        """Run pexpect as the user spawning the notebook

        This method attaches kerberos credentials to the command env if they
        exist.
        """

        user = pwd.getpwnam(self.user.name)
        uid = user.pw_uid
        env = os.environ
        krb_files = glob(f"/tmp/krb5cc_{uid}*")
        if krb_files:
            env["KRB5CCNAME"] = max(krb_files, key=os.path.getctime)

        popen_kwargs = dict(
            env=env,
            timeout=timeout,
            encoding="utf-8",
            preexec_fn=self.make_preexec_fn(self.user.name),
        )

        self.log.debug(f"Running: {cmd} as {self.user.name}")
        return popen_spawn.PopenSpawn(cmd, **popen_kwargs)

    async def remote_env(self, host=None):
        """Command with the `get_env` environment as the input to `/bin/env`

        Used to pass the necessary environment to the `jupyterhub-singleuser`
        command and isolate/hide the environment variables via `/bin/env`.
        """

        def env_str_to_dict(output):
            "Convert the output of `env` into a dict"

            d = {}
            lines = output.split("\n")
            for line in lines:
                divided = line.split("=")
                if len(divided) == 2:
                    var, val = divided
                    d[var] = val
                elif len(divided) == 1:
                    var = divided[0]
                    d[var] = ""
            return d

        if host:
            opts = self.ssh_opts(known_hosts=self.known_hosts)
            self.log.info(f"Collecting remote environment from {host}")
            child = self.spawn_as_user(
                f"ssh {opts} {host} 'source /etc/profile; env 2>/dev/null' 2>/dev/null"
            )
            child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=10)
            return env_str_to_dict(child.before)

    def get_env(self, other_env=None):
        """Get environment variables to be set in the spawned process."""

        def swap_host(url, hostname=""):
            if not hostname:
                return url
            parsed = urlparse(url)
            parsed = parsed._replace(netloc=hostname + ":" + str(parsed.port))
            return urlunparse(parsed)

        env = super().get_env()
        if other_env:
            env.update(other_env)
        unwanted_keys = set(["VIRTUAL_ENV", "SSH_ASKPASS"])
        for key in unwanted_keys:
            if key in env:
                del env[key]

        env["JUPYTERHUB_CLEANUP_SERVERS"] = self.cleanup_server
        env["JUPYTERHUB_CHECK_INTERVAL"] = self.hub_check_interval * 60
        if self.notebook_max_lifetime:
            env["JUPYTERHUB_MAX_LIFETIME"] = self.notebook_max_lifetime * 60 * 60

        # This is to account for running JupyterHub in a container since the
        # container hostname will be meaningless.
        env["JUPYTERHUB_API_URL"] = swap_host(
            env["JUPYTERHUB_API_URL"], hostname=self.hostname
        )

        env["JUPYTERHUB_ACTIVITY_URL"] = swap_host(
            env["JUPYTERHUB_ACTIVITY_URL"], hostname=self.hostname
        )

        env["JUPYTER_RUNTIME_DIR"] = os.path.join("/tmp", env["USER"], "sshspawner")

        # If the user starting their notebook is in the list of admins
        if self.user.name in self.user.settings.get("admin_users", []):
            env["JUPYTERHUB_ADMIN_ACCESS"] = 1
        else:
            env["JUPYTERHUB_ADMIN_ACCESS"] = 0

        return env

    def get_args(self):
        """Get the args to send to the jupyterhub-singleuser command

        Extends the default `get_args` command and adds arguments for security
        and specifically to make the SSHSpawner work.
        """

        args = super().get_args()
        if self.allow_origin_pattern:
            args.append(
                f"--SingleUserNotebookApp.allow_origin_pat={self.allow_origin_pattern}"
            )

        if self.idle_timeout:
            args.append(f"--MappingKernelManager.cull_idle_timeout={self.idle_timeout}")
        args.append("--KernelManager.transport=ipc")

        if self.local_logfile:
            args.append(f"2>&1 | tee -a {self.resource_path}/{self.local_logfile}")

        return args

    def stage_certs(self, paths, dest):
        shutil.move(paths["keyfile"], dest)
        shutil.move(paths["certfile"], dest)
        shutil.copy(paths["cafile"], dest)

        key_base_name = os.path.basename(paths["keyfile"])
        cert_base_name = os.path.basename(paths["certfile"])
        ca_base_name = os.path.basename(paths["cafile"])
        host = pipes.quote(self.user_options["host"])
        self.resource_path = os.path.join(self.resource_path, host)

        key = os.path.join(self.resource_path, key_base_name)
        cert = os.path.join(self.resource_path, cert_base_name)
        ca = os.path.join(self.resource_path, ca_base_name)

        return {
            "keyfile": key,
            "certfile": cert,
            "cafile": ca,
        }

    async def create_stop_script(self, stop_script):
        user = pwd.getpwnam(self.user.name)
        uid = user.pw_uid
        gid = user.pw_gid
        cmd = self.cmd[self.ssh_target]

        with open(stop_script, "w") as fh:
            fh.write(
                f"ps x | grep '{cmd[0]} --port={self.port}' | awk '{{print $1}}' | xargs kill"
            )
            shutil.chown(stop_script, user=uid, group=gid)
            os.chmod(stop_script, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    async def create_start_script(self, local_resource_path, remote_env=None):
        user = pwd.getpwnam(self.user.name)
        uid = user.pw_uid
        gid = user.pw_gid
        env = self.get_env(other_env=remote_env)
        cmd = self.cmd[self.ssh_target]

        pre_start_script = os.path.join(
            local_resource_path, f"pre_{self.start_notebook_cmd}"
        )
        start_script = os.path.join(local_resource_path, self.start_notebook_cmd)

        if self.ssh_target in self.conda_env_loc:
            if self.ssh_target in self.conda_env_name:
                env[
                    "PATH"
                ] += f':{os.path.join(self.conda_env_loc[self.ssh_target], "envs", self.conda_env_name[self.ssh_target], "bin")}'
            else:
                env[
                    "PATH"
                ] += f':{os.path.join(self.conda_env_loc[self.ssh_target], "bin")}'

        quoted_env = (
            ["env"]
            + [pipes.quote(f"{var}={val}") for var, val in env.items()]
            + [f"{os.path.join(self.resource_path, self.start_notebook_cmd)}"]
        )

        with open(pre_start_script, "w") as fh:
            fh.write(_script_template.format(" ".join(quoted_env)))
            shutil.chown(pre_start_script, user=uid, group=gid)
            os.chmod(pre_start_script, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        # environment + cmd + args
        cmd = [" ".join(cmd + self.get_args())]
        if self.ssh_target in self.pre_server_startup_script:
            cmd = [self.pre_server_startup_script[self.ssh_target]] + cmd

        with open(start_script, "w") as fh:
            fh.write(_script_template.format("\n".join(cmd)))
            shutil.chown(start_script, user=uid, group=gid)
            os.chmod(start_script, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    async def start(self):
        with TemporaryDirectory() as td:
            local_resource_path = td
            stop_script = os.path.join(local_resource_path, self.stop_notebook_cmd)

            user = pwd.getpwnam(self.user.name)
            uid = user.pw_uid
            gid = user.pw_gid
            host = pipes.quote(self.user_options["host"])
            self.resource_path = os.path.join(self.resource_path, host)
            self.ssh_target = host

            opts = self.ssh_opts(
                persist=self.ssh_control_persist_time, known_hosts=self.known_hosts
            )
            remote_env = await self.remote_env(host=self.ssh_target)

            if self.user.settings["internal_ssl"]:
                self.cert_paths = self.stage_certs(self.cert_paths, local_resource_path)

            ports_proc = self.spawn_as_user(
                f"ssh {opts} {self.ssh_target} /usr/bin/python {self.get_port_remote_location[self.ssh_target]}"
            )

            ports_proc.expect("[0-9]{1,5}\s[0-9]{1,5}")
            notebook_port, r_proxy_port = ports_proc.after.split()
            self.port = int(notebook_port)

            env = self.get_env(other_env=remote_env)

            if self.ssh_target in self.remote_notebook_env:
                # Specific code for the VSC, sometimes VSC_DATA is missing
                if self.remote_notebook_env[self.ssh_target] == "VSC_DATA":
                    # _vscuser = env["USER"]
                    _vscuser = self.spawn_as_user(
                        f"ssh {opts} {self.ssh_target} /usr/bin/whoami"
                    )
                    _vscuser.expect("vsc[0-9]+")
                    vscuser = _vscuser.after
                    if not vscuser.startswith('vsc'):
                        self.log.debug('Username is not correct!')
                        self.log.debug(_vscuser)
                        self.log.debug(vscuser)
                    self.notebook_path = f"/data/leuven/{vscuser[3:6]}/{vscuser}"
                else:
                    self.notebook_path = env[self.remote_notebook_env[self.ssh_target]]
                if not self.notebook_path.startswith("/"):
                    self.notebook_path = f"/{self.notebook_path}"

                if self.remote_notebook_folder:
                    self.notebook_path = os.path.join(
                        self.notebook_path, self.remote_notebook_folder
                    )
                if self.lab_enabled:
                    self.default_url = f"/lab/tree{self.notebook_path}"
                    self.notebook_dir = "/"
                else:
                    self.default_url = f"/tree{self.notebook_path}"
                    self.notebook_dir = "/"

                create_notebook_dir_proc = self.spawn_as_user(
                    f"ssh {opts} {self.ssh_target} mkdir -p {self.notebook_path}"
                )
                create_notebook_dir_proc.expect(pexpect.EOF)

            # Create the start script (part of resources)

            await self.create_start_script(local_resource_path, remote_env=remote_env)
            await self.create_stop_script(stop_script)

            # Set proper ownership to the user we'll run as
            for f in [local_resource_path] + [
                os.path.join(local_resource_path, f)
                for f in os.listdir(local_resource_path)
            ]:
                shutil.chown(f, user=uid, group=gid)

            # Create remote directory in user's home
            create_dir_proc = self.spawn_as_user(
                f"ssh {opts} {self.ssh_target} mkdir -p {self.resource_path}"
            )
            create_dir_proc.expect(pexpect.EOF)

            files = " ".join(
                [
                    os.path.join(local_resource_path, f)
                    for f in os.listdir(local_resource_path)
                ]
            )

            copy_files_proc = self.spawn_as_user(
                f"scp {opts} {files} {self.ssh_target}:{self.resource_path}/"
            )
            i = copy_files_proc.expect(
                [
                    ".*No such file or directory",
                    "ssh: Could not resolve hostname",
                    pexpect.EOF,
                ]
            )

            if i == 0:
                raise IOError(f"No such file or directory: {local_resource_path}")
            elif i == 1:
                raise HostNotFound(f"Could not resolve hostname {self.ssh_target}")
            elif i == 2:
                self.log.info(
                    f"Copied resources for {self.user.name} to {self.ssh_target}"
                )

            # Start remote notebook
            run_cmd = f"pre_{self.start_notebook_cmd}"
            start_notebook_child = self.spawn_as_user(
                f"ssh {opts} -L {self.port}:127.0.0.1:{self.port} {self.ssh_target} {os.path.join(self.resource_path, run_cmd)}",
                timeout=None,
            )

            self.proc = start_notebook_child.proc
            self.pid = self.proc.pid

            if self.ip:
                self.user.ip = self.ip
            else:
                self.ip = "127.0.0.1"
                self.user.ip = self.ip
            self.user.port = self.port

            return (self.ip, self.port)

    async def stop(self, now=False):
        """Stop the remote single-user server process for the current user.

        For the SSHSpawner, this means first attempting to stop the remote
        notebook and then killing the tunnel process (which should die once
        the notebook does).

        The `jupyterhub-singleuser` command has been modified to periodically
        poll the hub for contact and authorization. Failing these, it should
        think itself orphaned and shut itself down.
        """

        status = await self.poll()
        if status is not None and status != 255:
            return
        self.log.info(
            f"Stopping user {self.user.name}'s notebook at port {self.port} on host {self.ssh_target}"
        )
        host = pipes.quote(self.user_options["host"])
        self.resource_path = os.path.join(self.resource_path, host)

        stop_child = self.spawn_as_user(
            f"ssh {self.ssh_opts(known_hosts=self.known_hosts)} {self.ssh_target} {os.path.join(self.resource_path, self.stop_notebook_cmd)}"
        )
        stop_child.expect(pexpect.EOF)
        ret_code = stop_child.wait()
        if ret_code == 0:
            self.log.info("Notebook stopped")

        if self.pid > 0:
            self.log.debug("Killing %i", self.pid)

            await self._signal(signal.SIGKILL)

        # close the tunnel
        os.remove(self.ssh_socket)

    async def poll(self):
        """Poll the spawned process to see if it is still running and reachable

        If the process is still running, and we can connect to the remote
        singleuser server over the tunnel, we return None. If it is not
        running, or unreachable we return the exit code of the process if we
        have access to it, or 0 otherwise.
        """
        status = await super().poll()

        if status is not None:
            if status == 255 and not self._stopping:
                self._stopping = True
                await self.stop()
            return status
        elif not os.path.exists(self.ssh_socket) and not self._started:
            # tunnel is closed or non-existent
            return 0
        else:
            if self.user.settings["internal_ssl"]:
                protocol = "https"
                key = self.user.settings.get("internal_ssl_key")
                cert = self.user.settings.get("internal_ssl_cert")
                ca = self.user.settings.get("internal_ssl_ca")
                ctx = make_ssl_context(key, cert, cafile=ca)
            else:
                protocol = "http"
                ctx = None
            ip = self.ip or "127.0.0.1"
            url = f"{protocol}://{ip}:{self.port}"
            try:
                reachable = await wait_for_http_server(url, ssl_context=ctx)
            except Exception as e:
                if isinstance(e, TimeoutError):
                    e.reason = "timeout"
                    self.log.warning(
                        f"Unable to reach {self.user.name}'s server for 10 seconds. "
                        f"Giving up: {e}",
                    )
                    return 1
                else:
                    e.reason = "error"
                    self.log.warning(f"Error reaching {self.user.name}'s server: {e}")
                    return 2
            else:
                return None if reachable else 0
