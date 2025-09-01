import os
import os.path

######################
# Paths
######################

def _get_install_prefix():
    path_parts = __file__.split(os.path.sep)
    for i in range(len(path_parts) - 4, -1, -1):
        if path_parts[i] == 'lib' and path_parts[i + 1].startswith('python'):
            return os.path.sep.join(path_parts[:i]), False
    return os.path.sep.join(path_parts[:-2]), True

# Global paths
TMPDIR = os.path.join(os.environ.get('HOME', '.'), 'cougarnet-tmp')
INSTALL_PREFIX, loc = _get_install_prefix()
if loc:
    LIBEXEC_DIR = os.path.join(INSTALL_PREFIX, 'libexec')
else:
    LIBEXEC_DIR = os.path.join(INSTALL_PREFIX, 'libexec',  'cougarnet')

# Per instance paths
PID_FILE = 'pid'
ENV_FILE = 'env'
HOSTS_DIR = 'hosts'
HOSTS_INCLUDE_FILE = 'hosts_include'
COMM_SRV_SOCK = 'comm_srv_sock'
SYS_CMD_HELPER_SRV_SOCK = 'sys_cmd_helper_srv_sock'
SYS_CMD_HELPER_CLIENT_MAIN_SOCK = 'sys_cmd_helper_client_sock'

# Per hostname paths
PID_FILE_PER_HOST = 'pid'
COMM_CLIENT_SOCK = 'comm_client_sock'
CONFIG_FILE = 'config.json'
HOSTS_FILE = 'hosts'
TMUX_SOCK = 'tmux_sock'
STARTUP_SCRIPT = 'startup.sh'
SYS_CMD_HELPER_CLIENT_MAIN_SOCK_PER_HOST = 'sys_cmd_helper_sock'
SYS_NET_HELPER_RAW_DIR = 'sys_net_helper_sock_raw'
SYS_NET_HELPER_USER_DIR = 'sys_net_helper_sock_user'

# Generic system paths
PROC_NS_DIR_TEMPLATE = '/proc/%d/ns/'
RUN_NETNS_DIR = '/run/netns/'


######################
# Other options
######################

LOG_FORMAT = '%(levelname)s: (%(name)s) %(message)s'

VIRT_HOST_STARTUP_TIMEOUT = 6
FALSE_STRINGS = ('off', 'no', 'n', 'false', 'f', '0')

TERM = "lxterminal"

SYS_HELPER_MODULE = "cougarnet.virtualnet.sys_helper"
HOSTINIT_MODULE = "cougarnet.virtualnet.hostinit"
HOSTREADY_MODULE = "cougarnet.virtualnet.hostready"
RAWPKT_HELPER_MODULE = "cougarnet.sim.rawpkt_helper"

MAIN_WINDOW_NAME = "main"
CMD_WINDOW_NAME = "prog"
ALLOWED_ROUTERS = set(['rip', 'ripng'])
