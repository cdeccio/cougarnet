import os

######################
# Paths
######################

# Global paths
TMPDIR = os.path.join(os.environ.get('HOME', '.'), 'cougarnet-tmp')

# Per instance paths
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

 
######################
# Other options
######################

VIRT_HOST_STARTUP_TIMEOUT = 6
FALSE_STRINGS = ('off', 'no', 'n', 'false', 'f', '0')

TERM = "lxterminal"

SYS_HELPER_MODULE = "cougarnet.virtualnet.sys_helper"
HOSTINIT_MODULE = "cougarnet.virtualnet.hostinit"
RAWPKT_HELPER_MODULE = "cougarnet.sim.rawpkt_helper"

MAIN_WINDOW_NAME = "main"
CMD_WINDOW_NAME = "prog"
ALLOWED_ROUTERS = set(['rip', 'ripng'])
