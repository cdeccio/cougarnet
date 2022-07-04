'''
Various utility functions for Cougarnet.
'''

import binascii
import socket
import subprocess
import time

def mac_str_to_binary(mac_str):
    '''Given a MAC address in presentation format as a string, return the
    equivalent bytes object.'''

    return binascii.unhexlify(mac_str.replace(':', ''))

def mac_binary_to_str(mac_bin):
    '''Given a bytes object, return the equivalent MAC address in presentation
    format as a string.'''

    return ':'.join(['%02x' % b for b in mac_bin])

def ip_str_to_binary(ip_str):
    '''Given an IPv4 or IPv6 address in presentation format as a string, return
    the equivalent bytes object.'''

    if ':' in ip_str:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    return socket.inet_pton(af, ip_str)

def ip_binary_to_str(ip_bin):
    '''Given a bytes object, return the equivalent IPv4 or IPv6 address in
    presentation format as a string.'''

    if len(ip_bin) > 4:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    return socket.inet_ntop(af, ip_bin)

def pid_is_running(pid):
    '''Return True if the process associated with a given pid (int) is running;
    False otherwise.'''

    cmd = ['ps', '-p', str(pid)]
    p = subprocess.run(cmd, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return p.returncode == 0

def kill(pid, sig, elevate_if_needed=False):
    '''Send a signal (e.g., TERM, KILL) to a process.  If a permissions error
    is detected, and elevate_if_needed is True, then send the same signal again
    as root.  Return True if the signal was sent successfully; False
    otherwise.'''

    cmd = ['kill', f'-{sig}', str(pid)]
    p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, check=False)
    if p.returncode != 0:
        stderr = p.stderr.decode('utf-8').lower()
        #XXX this does not work for non-English
        if 'not permitted' in stderr and elevate_if_needed:
            cmd.insert(0, 'sudo')
            p = subprocess.run(cmd, check=False,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0

def kill_until_terminated(pid, elevate_if_needed=False):
    '''Send TERM to a process.  If the process continues to run, then send
    KILL.  In both cases, elevate if a permissions error is detected, and
    elevate_if_needed is True.'''

    sigs = ('TERM', 'KILL')
    for sig in sigs:
        kill(pid, sig, elevate_if_needed=elevate_if_needed)
        if pid_is_running(pid):
            time.sleep(0.2)
        if pid_is_running(pid):
            continue
        break
