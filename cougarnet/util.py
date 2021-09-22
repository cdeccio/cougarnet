import os
import subprocess


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
