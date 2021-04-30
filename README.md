# SSH Spawner
(Forked and modified from [LLNL/SSHSpawner](https://github.com/LLNL/SSHSpawner))

Extends the JupyterHub LocalProcessSpawner to instead launch notebooks on
a remote host (e.g. a login node).

## Overview

The basic premise of the SSHSpawner is that it performs the normal Jupyter
Notebook start on a remote host of choice. To make the remote notebook appear
as a local one to Jupyter (and avoid opening several high number ports on
_all_ remote hosts), an ssh tunnel is started that directs the remote notebook
port to localhost on the same port on the JupyterHub server.

In general the spawner:

1. Looks up credentials (kerberos, certificates) to attach to operations that
require them (like ssh)
   * System and user ssh configurations are used as we spawn `ssh` via `Popen`, it is therefore useful to configure `/etc/ssh/ssh_config` on the hub host with the configured hostnames and allow users to further configure their own usernames (if different from the hub host) and ssh keys in their own user config.
2. Asks the user for the host they want to spawn on
   * Displayed hosts can have a prefix removed, allowing system-wide ssh configuration of remote hosts using a prefix such as `jupyterhub-<HOST>`
3. Creates a folder of resources to move to the remote host:
   * All the certs for encrypting communication between the hub and notebook
   * The script used to start a notebook--this is basically the standard
   command JupyterHub uses to start a notebook, but put into a script to avoid
   OAuth credentials from showing up in `ps`
4. Attaches credentials, moves resources to the remote host, and invokes the
`start-notebook` command.
5. Polls the notebook using a single http request on an interval.

## Use

To enable the spawner, import this class in the jupyterhub\_config.py file
and set the spawner class to SSHSpawner:

```python
from sshspawner import SSHSpawner
c.JupyterHub.spawner_class = SSHSpawner
```

See `sshspawner.py` for all config options

The following are some of the more useful configuration options:

| Parameter (c.SSHSpawner.\<option>)| Default       | Description   |	
| :-------------------------------- |:-------------:| :-------------|
| `ssh_host_prefix`	                  |	None      | A prefix to remove from server names in an ssh config file for displaying in the html options when starting a server
| `ssh_hosts`                       | `[]`          | A list of the remote hosts to be made available for starting a server on
| `cmd`           	               |	`{[]}`	    | `cmd` is now a dict, allowing per host configuration of the cmd to be started
| `conda_env_loc`  		            | `{}`          | If using conda, remote location of conda environment with jupyter installed (root conda path with `bin` folder), per server option
| `conda_env_name`  		            | `{}`          | If using conda, name of the conda env with jupyter installed to activate. Per server option.
| `remote_notebook_env`             | `{}`          | Remote environment variable containing the path to a location for notebook storage. Per server option. 
| `pre_server_startup_script`	      | `{}`          | Bash code to run (multiline string) prior to starting remote server. Can be used to intialise a module system to, for example, load a newer version of `Git`. Per server command.


## Known Issues

* `internal_ssl` settings have not been properly checked.
