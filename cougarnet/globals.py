import os

######################
# Paths
######################

# Global paths
TMPDIR = os.path.join(os.environ.get('HOME', '.'), 'cougarnet-tmp')

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

# FRR-related paths
FRR_CONF_DIR = '/etc/frr/'
FRR_RUN_DIR = '/var/run/frr/'
FRR_PROG_DIR = '/usr/lib/frr'
FRR_ZEBRA_PROG = os.path.join(FRR_PROG_DIR, 'zebra')
FRR_RIPD_PROG = os.path.join(FRR_PROG_DIR, 'ripd')
FRR_RIPNGD_PROG = os.path.join(FRR_PROG_DIR, 'ripngd')
FRR_ZEBRA_PID_FILE = 'zebra.pid'
FRR_RIPD_PID_FILE = 'ripd.pid'
FRR_RIPNGD_PID_FILE = 'ripngd.pid'
FRR_ZEBRA_CONF_FILE = 'zebra.conf'
FRR_RIPD_CONF_FILE = 'ripd.conf'
FRR_RIPNGD_CONF_FILE = 'ripngd.conf'
FRR_ZEBRA_VTY_FILE = 'zebra.vty'
FRR_RIPD_VTY_FILE = 'ripd.vty'
FRR_RIPNGD_VTY_FILE = 'ripngd.vty'
FRR_ZSERV_FILE = 'zserv.api'

# Generic system paths
PROC_NS_DIR_TEMPLATE = '/proc/%d/ns/'
RUN_NETNS_DIR = '/run/netns/'


######################
# Other options
######################

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
