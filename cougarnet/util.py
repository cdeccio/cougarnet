import binascii
import socket
import subprocess
import time

def mac_str_to_binary(mac_str):
    return binascii.unhexlify(mac_str.replace(':', ''))

def mac_binary_to_str(mac_bin):
    return ':'.join(['%02x' % b for b in mac_bin])

def ip_str_to_binary(ip_str):
    if ':' in ip_str:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    return socket.inet_pton(af, ip_str)

def ip_binary_to_str(ip_bin):
    if len(ip_bin) > 4:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    return socket.inet_ntop(af, ip_bin)

def pid_is_running(pid):
    cmd = ['ps', '-p', str(pid)]
    p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT)
    return p.returncode == 0

def kill(pid, sig, elevate_if_needed=False):
    cmd = ['kill', f'-{sig}', str(pid)]
    p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE)
    if p.returncode != 0:
        stderr = p.stderr.decode('utf-8').lower()
        if 'not permitted' in stderr and elevate_if_needed:
            cmd.insert(0, 'sudo')
            p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
    return p.returncode == 0

def kill_until_terminated(pid, elevate_if_needed=False):
    sigs = ('TERM', 'KILL')
    for sig in sigs:
        kill(pid, sig, elevate_if_needed=elevate_if_needed)
        if pid_is_running(pid):
            time.sleep(0.2)
        if pid_is_running(pid):
            continue
        break
