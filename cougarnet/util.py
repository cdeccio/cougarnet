import binascii
import socket
import os
import subprocess


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


def remove_if_exists(file, allow_root=False):
    '''
    Check if a file exists, if it does exist, remove it.
    If `allow_root` is set to true, try to remove it without privileges,
    then try again with privileges.
    '''
    if os.path.exists(file):
        try:
            os.remove(file)
        except PermissionError as e:
            if allow_root:
                cmd = ["sudo", "rm", file]
                subprocess.run(cmd)
            else:
                raise e
