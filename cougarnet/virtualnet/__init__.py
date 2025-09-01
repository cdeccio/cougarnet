import argparse
import logging
import os
import signal
import subprocess
import sys
import tempfile

from cougarnet.errors import *
from cougarnet.globals import *

from .manager import VirtualNetwork


logger = logging.getLogger(__name__)


def check_requirements(args):
    '''Check the basic requirements for Cougarnet to run, including effective
    user, sudo configuration, presence directories, and presence of certain
    programs.'''

    if os.geteuid() == 0:
        sys.stderr.write('Please run this program as a non-privileged user.\n')
        sys.exit(1)

    # make sure working directories exist
    cmd = ['mkdir', '-p', TMPDIR]
    subprocess.run(cmd, check=True)

    if args.display or args.display_file:
        try:
            from pygraphviz import AGraph
        except ImportError:
            sys.stderr.write('Pygraphviz is required for the --display and ' + \
                    '--display-file options\n')
            sys.exit(1)

        if args.display:
            try:
                subprocess.run(['graph-easy', '--help'], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, check=True)
            except subprocess.CalledProcessError:
                pass
            except OSError as e:
                sys.stderr.write('graph-easy is required with the ' + \
                        f'--display: {str(e)}.\n')
                sys.exit(1)


    if args.wireshark is not None:
        try:
            subprocess.run(['wireshark', '-h'], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=True)
        except OSError as e:
            sys.stderr.write('wireshark is required with the ' + \
                    f'--wireshark/-w option: {str(e)}.\n')
            sys.exit(1)

    try:
        subprocess.run(['ovs-vsctl', '-V'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f'Open vSwitch is required: {str(e)}\n')
        sys.exit(1)

def warn_on_sigttin(sig, frame):
    '''Warn when SIGTTIN is received.  This is only necessary because of some
    issues with extraneous signals being unexpectedly received, possibly a side
    effect of running in a virtual machine.'''

    sys.stderr.write('Warning: SIGTTIN received\n')

def main():
    '''Process command-line arguments, instantiate a VirtualNetwork instance
    from a file, and run and clean-up the virtual network.'''

    parser = argparse.ArgumentParser()
    parser.add_argument('--wireshark', '-w',
            action='store', type=str, default=None,
            metavar='LINKS',
            help='Start wireshark for the specified links ' + \
                    '(host1-host2[,host2-host3,...])')
    parser.add_argument('--verbose', '-v',
            action='store_const', const=True, default=False,
            help='Use verbose output')
    parser.add_argument('--display',
            action='store_const', const=True, default=False,
            help='Display the network configuration as text')
    parser.add_argument('--vars',
            action='store', type=str, default=None,
            help='Specify variables to be replaced in the ' + \
                    'configuration file (name=value[,name=value,...])')
    parser.add_argument('--start',
            action='store', type=int, default=0,
            help='Specify a number of seconds to wait before ' + \
                    'the scenario is started.')
    parser.add_argument('--stop',
            action='store', type=int, default=None,
            help='Specify a number of seconds after which the scenario ' + \
                    'should be halted.')
    parser.add_argument('--terminal',
            action='store', type=str, default=None,
            metavar='HOSTNAMES',
            help='Specify which virtual hosts should launch a terminal ' + \
                    '(all|none|host1[,host2,...])')
    parser.add_argument('--disable-ipv6',
            action='store_const', const=True, default=False,
            help='Disable IPv6')
    parser.add_argument('--display-file',
            type=argparse.FileType('wb'), action='store',
            metavar='FILE',
            help='Print the network configuration to a file (.png)')
    parser.add_argument('config_file',
            type=argparse.FileType('r'), action='store',
            help='File containing the network configuration')
    args = parser.parse_args(sys.argv[1:])

    # configure logging
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.NOTSET)

    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter(fmt=LOG_FORMAT))
    if args.verbose:
        h.setLevel(logging.DEBUG)
    else:
        h.setLevel(logging.INFO)
    root_logger.addHandler(h)

    check_requirements(args)

    signal.signal(21, warn_on_sigttin)

    try:
        tmpdir = tempfile.TemporaryDirectory(dir=TMPDIR)
    except PermissionError:
        sys.stderr.write('Unable to create working directory.  Check ' + \
                f'permissions of {TMPDIR}.\n')
        sys.exit(1)

    if args.terminal is None:
        terminal_hosts = []
    else:
        terminal_hosts = args.terminal.split(',')

    if args.vars:
        config_vars = dict([p.split('=', maxsplit=1) \
                for p in args.vars.split(',')])
    else:
        config_vars = {}

    ipv6 = not args.disable_ipv6

    try:
        net = VirtualNetwork.from_file(args.config_file,
                terminal_hosts, config_vars, tmpdir.name,
                ipv6, args.verbose)
    except ConfigurationError as e:
        sys.stderr.write(f'{args.config_file.name}:{e.lineno}: ' + \
                f'{str(e)}\n')
        sys.exit(1)

    wireshark_ints = []
    if args.wireshark is not None:
        wireshark_ints = args.wireshark.split(',')
        for intf in wireshark_ints:
            intf = intf.strip()
            try:
                host1, host2 = intf.split('-')
            except ValueError:
                sys.stderr.write('Invalid link passed to the ' + \
                        f'--wireshark/-w option: {intf}\n')
                sys.exit(1)
            if host1 not in net.host_by_name:
                sys.stderr.write('Invalid link passed to the ' + \
                        f'--wireshark/-w option; host does not exist: {host1}\n')
                sys.exit(1)
            if host2 not in net.host_by_name:
                sys.stderr.write('Invalid link passed to the ' + \
                        f'--wireshark/-w option; host does not exist: {host2}\n')
                sys.exit(1)
            if host2 not in net.host_by_name[host1].neighbor_by_hostname:
                sys.stderr.write('Invalid link passed to the ' + \
                        f'--wireshark/-w option; link does not exist: {intf}\n')
                sys.exit(1)
        wireshark_ints = [f'{intf}-ghost' for intf in wireshark_ints]

    if args.display:
        net.display_to_screen()
    if args.display_file:
        net.display_to_file(args.display_file)

    err = ''
    try:
        oldmask = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
        net.config()
        net.start(args.start, wireshark_ints)
        signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
        sys.stdout.write('Ctrl-c to quit\n')
        net.message_loop(args.stop)
    except (StartupError, SysCmdError) as e:
        err = f'{str(e)}\n'
    except KeyboardInterrupt:
        pass
    finally:
        # sometimes ctrl-c gets sent twice, interrupting with SIGINT a second
        # time, and cleanup does not happen.  So here we tell the code to
        # ignore SIGINT, so cleanup can finish.  If you really want to kill it,
        # then use SIGTERM or (gasp!) SIGKILL.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        net.cleanup()

    if err:
        sys.stderr.write(err)
        sys.exit(1)
