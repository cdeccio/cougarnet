import json
import os
import subprocess

from cougarnet.sys_helper.manager import SysCmdHelperManagerStarted

sys_cmd_helper = None

def _init_helper():
    global sys_cmd_helper
    helper_sock_paths = json.loads(os.environ['COUGARNET_SYS_CMD_HELPER_SOCK'])
    sys_cmd_helper = SysCmdHelperManagerStarted(
            helper_sock_paths['remote'], helper_sock_paths['local'])
    sys_cmd_helper.start()

def sys_cmd(cmd, check=False):
    global sys_cmd_helper
    if sys_cmd_helper is None:
        _init_helper()
    status = sys_cmd_helper.cmd(cmd)
    if not status.startswith('0,') and check:
        try:
            err = status.split(',', maxsplit=1)[1]
        except (ValueError, IndexError):
            err = 'Unknown error'
        cmd_str = ' '.join(cmd)
        #XXX need to raise this differently
        raise Exception(f'Command failed: {cmd_str}: {err}')

def sys_cmd_pid(cmd, check=False):
    pid = os.environ.get('COUGARNET_PID', '0')
    return sys_cmd([cmd[0]] + [pid] + cmd[1:], check=check)
