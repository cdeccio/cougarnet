
# Cougarnet

Cougarnet creates a virtual network for learning network configuration and
protocols.  It takes as input a [network configuration
file](#network-configuration-file).  Using the configuration as a guide, it
creates [virtual hosts](#virtual-hosts) and [virtual links](#virtual-links)
between them.  It can also add MAC and IP address information to interfaces,
specify bandwidth, (propagation) delay, or loss to links.

Perhaps the most power feature of Cougarnet is the ability to either use the
built-in Linux network stack or capture raw frames only.  The former is useful
for configuring and using a network with built-in tools (e.g., `ping`,
`traceroute`), while the latter is useful for implementing the protocol stack in
software.  Additionally, there can be a mixture--some hosts that use native
stack and some that do not.


# Table of Contents
 - [Installation](#installation)
 - [Getting Started](#getting-started)
   - [Two Hosts, Directly Connected](#two-hosts-directly-connected)
   - [Three Hosts Connected by a Switch](#three-hosts-connected-by-a-switch)
   - [Hosts Connected Across Multiple Switches and Routers](#hosts-connected-across-multiple-switches-and-routers)
 - [Virtual Hosts](#virtual-hosts)
   - [Configuration](#configuration)
   - [Hostnames](#hostnames)
   - [Interface Names](#interface-names)
   - [Communicating with the Calling Process](#communicating-with-the-calling-process)
   - [Name Resolution](#name-resolution)
   - [Host Types](#host-types)
   - [Routes](#routes)
   - [Environment](#environment)
   - [Running Programs](#running-programs)
   - [Sending and Receiving Frames](#sending-and-receiving-frames)
   - [Scheduling Events](#scheduling-events)
   - [Cancelling Events](#cancelling-events)
 - [Virtual Links](#virtual-links)
   - [Configuration](#configuration-1)
   - [Bi-Directionality of Link Attributes](#bi-directionality-of-link-attributes)
   - [VLAN Attributes](#vlan-attributes)
 - [Network Configuration File](#network-configuration-file)
 - [Command-Line Usage](#command-line-usage)


# Installation

The following are dependencies for Cougarnet:

 - [sudo](https://www.sudo.ws/)
 - [Open vSwitch](https://www.openvswitch.org/)
 - [tmux](https://github.com/tmux/tmux/)
 - [LXTerminal](https://wiki.lxde.org/en/LXTerminal)
 - [PyGraphviz](https://pygraphviz.github.io/)
 - [Graph::Easy](https://metacpan.org/pod/Graph::Easy)
 - [Wireshark](https://www.wireshark.org/) - (optional, but recommended)
 - [socat](http://www.dest-unreach.org/socat/) - (used only in examples in the documentation)

To install these on a Debian system, run the following:

```
$ sudo apt install openvswitch-switch tmux lxterminal python3-pygraphviz libgraph-easy-perl wireshark socat
```

Of course, this assumes that you already have `sudo` installed and that your user is
allowed to call it.

Additionally, `sudo` should be configured such that your user can call it without requiring a
password (i.e., with the `NOPASSWD` option).  For example, your `/etc/sudoers`
file might contain the following:

```sudoers
%sudo   ALL=(ALL:ALL) NOPASSWD: ALL
```

To install Cougarnet, run the following:

```bash
$ python3 setup.py build
$ sudo python3 setup.py install
```


# Getting Started

This section provides three examples of Cougarnet usage.


## Two Hosts, Directly Connected

To get started, let's create a simple network configuration.  Create a file
called `two-node-direct.cfg` with the following contents:

```
NODES
h1
h2

LINKS
h1,10.0.0.1/24 h2,10.0.0.2/24
```

This simple configuration results in a network composed of two hosts, named
`h1` and `h2`.  There is a single link between them.  For the link between `h1`
and `h2`, `h1`'s interface will have an IPv4 address of 10.0.0.1, and `h2` will
have an IPv4 address of 10.0.0.2.  The `/24` indicates that the length of the
IPv4 prefix associated with that link is 24 bits, i.e., 10.0.0.0/24.

Start Cougarnet with this configuration by running the following command:

```bash
$ cougarnet two-node-direct.cfg
```

When it starts up, it will launch two new terminals.  One will be associated
with the virtual host `h1` and the other with `h2`.  The prompt at each should
indicate which is which.

Each each terminal, run the following to see the network configuration:

```bash
$ ip addr
```

Then run the following on each to see the hostname:

```bash
$ hostname
```

Note first that each virtual host sees only its own interface. Also note that
each host is configured with the address from the configuration file.

Next, from the `h2` terminal, run the following:

```bash
h2$ tcpdump -l
```

(Note that in this example and elsewhere in this document `h2$` simply
indicates that it is the prompt corresponding to `h2`.)

The `-l` option to `tcpdump` ensures that line-based buffering is used, so the
output is printed as soon as it is generated.

Now from the `h1` terminal, run the following:

```bash
h1$ ping h2
```

You should see activity on both terminals.  The `tcpdump` output on `h2` shows
the ICMP packets resulting from the `ping` command issued on `h1`, as well as
the responses being returned by `h2`.  The `ping` output on `h1` shows the
status of the ICMP messages leaving `h1` and the response messages coming from
`h2`.

Now, enter `Ctrl`+`c` on each terminal to stop the two programs.  Finally,
return to the terminal on which you ran the `cougarnet` command, and enter
`Ctrl`+`c`.

Congratulations!  You have just completed a simple Cougarnet excercise!


## Three Hosts Connected by a Switch

Let's now add a switch to the previous example, so we can connect three nodes
together on the same LAN.  Create a new file called `three-node-switch.cfg` with
the following contents:

```
NODES
h1
h2
h3
s1 type=switch,terminal=false

LINKS
h1,10.0.0.1/24 s1
h2,10.0.0.2/24 s1
h3,10.0.0.3/24 s1
```

This configuration results in a network composed of three hosts, all connected
to a single switch, `s1`.  Each host has an IP address in the prefix
10.0.0.0/24 subnet.

Start Cougarnet with this configuration by running the following command:

```bash
$ cougarnet three-node-switch.cfg
```

When it starts up, it will launch three new terminals, associated with `h1`,
`h2`, and `h3`.  No terminal will appear for `s1` because `terminal=false` was
specified in the configuration file.

This time let's use Wireshark to capture packets.  Wireshark can be launched by
using the menu of your desktop environment or from a terminal, but it cannot be
launched from any of the terminals running your virtual hosts (i.e., `h1`,
`h2`, `h3`).  From the open Wireshark window, click the "Capture Options"
button (the gear icon).  Select interfaces `h2-s1-ghost` and `h3-s1-ghost`.
(You can select multiple by holding `Ctrl` when clicking.)  Those names might
seem a little confusing.  The way they should be understood is "`h2`'s
interface that is connected to `s1`" and "`h3`'s interface that is connected to
`s1`", respectively. The `-ghost` extension is simply part of a convention
needed to get Cougarnet to use Wireshark properly. See
[Interface Names](#interface-names) for more.  Now click "Start" to begin
capturing packets at those interfaces.

Now let's begin communicating!  First, let's split `h1`'s terminal into two.
Click on `h1` terminal, and press `Ctrl`+`b` then `"` (double quote).  Your
terminal is running an instance of [tmux](https://github.com/tmux/tmux/), and
the key strokes you just entered split the terminal horizontally.  panes.  To
switch back and forth between the two panes, press `Ctrl`+`b` followed by the
up or down arrow, to move up or down, respectively.

In one pane of `h1`, enter the following command:

```bash
h1$ ping h2
```

While that is running, switch panes, and enter enter the following:

```bash
h1$ ping h3
```

You should now see a lot of activity in your Wireshark window!  In particular,
you should see ICMP (Echo) request and reply packets between `10.0.0.1` (`h1`)
and `10.0.0.2` (`h2`) and between `10.0.0.1` (`h1`) and `10.0.0.3` (`h3`).

Now return to the terminal on which you ran the `cougarnet` command, and enter
`Ctrl`+`c`.  Then close Wireshark.

See the sections on [Virtual Links](#virtual-links) and
[VLAN Attributes](#vlan-attributes) to see what else is possible with switches.


## Hosts Connected Across Multiple Switches and Routers

In our final introductory example, we introduce routers, for network-layer
forwarding.  Create a new file called `four-node-multi-lan.cfg` with the
following contents:

```
NODES
h1 routes=0.0.0.0/0|s1|10.0.0.30
h2 terminal=false,routes=0.0.0.0/0|s1|10.0.0.30
h3 routes=0.0.0.0/0|s2|10.0.1.30
h4 terminal=false,routes=0.0.0.0/0|s2|10.0.1.30

s1 type=switch,terminal=false
s2 type=switch,terminal=false

r1 type=router,terminal=false,routes=10.0.1.0/24|r2|10.100.0.2
r2 type=router,terminal=false,routes=10.0.0.0/24|r1|10.100.0.1

LINKS
h1,10.0.0.1/24 s1
h2,10.0.0.2/24 s1
s1 r1,10.0.0.30/24
r1,10.100.0.1/30 r2,10.100.0.2/30
s2 r2,10.0.1.30/24
h3,10.0.1.1/24 s2
h4,10.0.1.2/24 s2
```

This simple configuration in two LANs (technically three, if you consider the
link between the routers), separated by two routers.  Each host and router is
provided entries for their routing table, so they can send packets out of their
LAN.  See [Routes](#routes) for more information.

This time we are going to start the network with additional options:

```bash
$ cougarnet --display --wireshark h3-s2 four-node-multi-lan.cfg
```

The `--display` option prints out a text-based drawing of the topology.  For a
slightly more detailed drawing, try the `--display-file` option.  The
`--wireshark` option simplifies packet capture setup.  When interfaces are
specified with the `--wireshark` option (`h3-h2`, in this case), Cougarnet
automatically starts wireshark and begins capturing on those interfaces.

Now enter the following command on `h1`'s terminal:

```bash
h1$ ping h3
```

You should again see ICMP Echo activity in Wireshark, captured at `h3`'s only
interface.  You might also notice that the packets arriving from 10.0.0.1 have
a smaller time-to-live (TTL) value, as it has decreased one for each hop
(router) traversed.

Again return to the terminal on which you ran the `cougarnet` command, and enter
`Ctrl`+`c`.  Then close Wireshark.


# Virtual Hosts

Each virtual host is actually just a process that is running in its own Linux
namespace (see the `man` page for `namespaces(7)`).  Specifically, it is a
process spawned with the `unshare` command.  The `--mount`, `--net`, and
`--uts` options are passed to `unshare` command, the result of which is that
(respectively):
 - any filesystem mounts created (i.e., with the `mount` command) are only seen
   by the process, not by the whole system;
 - the network stack, including interfaces, address configuration, firewall,
   and more, are specific to the process and are not seen by the rest of the
   system; and
 - the hostname is specific to the process.

With only these options in use, the virtual hosts all still have access to the
system-wide filesystem and all system processes (Note that the former could be
changed if `unshare` were called with `--root`, and the latter could be changed
if `unshare` were called with `--pid`, but currently that is not an option).


## Configuration

In the Cougarnet configuration file, a host is designated by a hostname on a
single line in the `NODES` section of the file. Consider the `NODES` section of
the [example configuration given previously](#getting-started):

```
NODES
h1
h2
```

This creates two virtual hosts, `h1` and `h2` with their
[hostnames](#hostnames) set accordingly.


### Additional Options

Additional options can be specified for any host.  For example, we might like
to provide `h1` with additional configuration, such as the following:

```
NODES
h1 type=switch,terminal=false
h2
```

In this case, h1 is desginated as a switch, and no terminal will be started for
`h1` as would normally be the case.

In general, the syntax for a host is:

```
<hostname> [name=val[,name=val[...]]
```

That is, if there are additional options, there is a space after the hostname,
and those options come after the space. The options consist of a comma-delimited
list of name-value pairs, each name connected to its value by `=`.  The defined
host option names are the following, accompanied by the expected value:
 - `native_apps`: a boolean (i.e., `true` or `false`) indicating whether or not
   the native network stack should be used.  Default: `true`.
 - `terminal`: a boolean (i.e., `true` or `false`) indicating whether or not a
   terminal should be spawned.  Sometimes neither an interactive interface with
   a virtual host nor console output is necessary, in which case `false` would
   be appropriate.  An example of this is if a script is designated to be run
   automatically with the host using the `prog` attribute.  Default: `true`.
 - `type`: a string representing the type of node.  The supported types are:
   `host`, `switch`, `router`.  Default: `host`. See [VLAN
   Attributes](#vlan-attributes) and [Routes](#routes) for more information on
   behavior specific to switches and routers, respectively.
 - `routes`: a string containing one or more IP forwarding rules for the host.
   Each route consists of a three-tuple specifying IP prefix, outgoing
   interface (designated by neighboring node on that interface), and next hop
   IP address, delimited with a pipe (`|`).  If there is no next hop, then the
   third element is simply blank.  Multiple forwarding rules are delimited with
   a semi-colon.  For example, the following would create a single, default
   route, for `h2`, using the interface `h1` as the outgoing interface and
   `10.0.0.6` as the next hop (i.e., the router).
   `0.0.0.0/0|h1|10.0.0.6`.  Default: no routes except for those corresponding
   to local subnets.  See [Routes](#routes) for more information.
 - `prog`: a string representing a program and its arguments, which are to be
   run, instead of an interactive shell.  The program path and its arguments
   are delimited by `|`.  For example, `echo|foo|bar` would execute
   `echo foo bar`.  Default: execute an interactive shell.  See [Running
   Programs](#running-programs) for more information.


## Hostnames

When started, the hostname of a virtual host is set according to the name given
in the configuration.  This can be seen in the title of the terminal as well as
the command-line prompt.  You can also retrieve the hostname by simply running
the following from the command line:

```bash
$ hostname
```

Or it can be retrieved using Python with the following:

```python
#!/usr/bin/python3
import socket
hostname = socket.gethostname()
```


## Interface Names

The interface names for a given [link](#virtual-links) are derived from the
name of the current host and the host it connects to on that link.  For
example, if there is a link connecting host `h1` and host `h2`, then `h1`'s
interface will be called `h1-h2`, and `h2`'s interface will be called `h2-h1`.
That helps greatly with identification.  The interfaces for a host, and their
respective configurations, can be viewed by running the following from the
command line:

```bash
$ ip addr
```

The interface names alone can be retrieved by listing the contents of the
special directory `/sys/class/net`.  For example:

```bash
$ ls /sys/class/net
```

Or to show all interfaces except loopback interfaces (i.e., starting with `lo`):

```bash
$ ls -l /sys/class/net | awk '$9 !~ /^lo/ { print $9 }'
```

The equivalent Python code is the following:

```python
#!/usr/bin/python3
import os
ints = [i for i in os.listdir('/sys/class/net/') if not i.startswith('lo')]
```


## Communicating with the Calling Process

Often it is useful for the virtual host to send messages back to the process
that invoked all the virtual hosts (i.e., the `cougarnet` process).  This
enables the logs for all messages to be received and printed in a single
location.  To accomplish this, each virtual process has the following
environment variables set:
 - `COUGARNET_COMM_SOCK` - the filesystem path corresponding to the remote UNIX
   domain socket (i.e., family `AF_UNIX`) of type `SOCK_DGRAM`.  Once all the
   virtual machines are started, the `cougarnet` process will print to standard
   output all messages received on this socket.
 - `COUGARNET_MY_SOCK` - the filesystem path to which a local UNIX domain socket
   should be bound to communicate with the remote socket.

For example, the following command, issued from a virtual host, will result in
a UDP datagram being sent to the UNIX domain socket on which the `cougarnet`
process is listening.

```bash
$ echo -n hello world | socat - UNIX-SENDTO:$COUGARNET_COMM_SOCK,bind=$COUGARNET_MY_SOCK
```

The equivalent Python code is the following:

```python
import os
import socket

sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
sock.bind((os.environ['COUGARNET_MY_SOCK']))
sock.connect(os.environ['COUGARNET_COMM_SOCK'])
sock.send('hello world'.encode('utf-8'))
```

The `cougarnet` process will print a single line of output that will look
something like this:

```
13.766   h1  hello world
```

The three components of the output message can be explained as follows:
 - *Relative time* (`13.766`): the relative time, i.e., the number of seconds
   that have elapsed since the virtual hosts were started by the `cougarnet`
   process.
 - *Hostname* (`h1`): the hostname of the virtual host from which the message
   was sent.  Note that the hostname is found by looking up the "address" (i.e.,
   the path corresponding to the UNIX socket) of the peer--that is, the virtual
   host that sent the message--in a table maintained by the `cougarnet` process.
   Thus, a virtual host must `bind()` the socket to the path corresponding to
   the `COUGARNET_MY_SOCK` environment variable, or the identity of the message
   will be unknown.
 - *Message* (`hello world`): the actual message to be logged and/or printed.

The `BaseHost` class has a function `log()` which can be used to issue
messages.  So if you subclass `BaseHost` and then call `log()`, it will handle
socket functions for you.


## Name Resolution

Every virtual host has its own `/etc/hosts`, which contains a mapping of the
names and IP addresses of all virtual hosts in the virtual network.  That
allows apps such as `ping` to use hostname instead of IP address exclusively
(see the [example given previously](#getting-started)).


## Host Types

The host types (i.e., `host`, `router`, `switch`) are intended to give special
behavior to the virtual host, depending on the type.  For example, when a host
of type `router` uses native apps mode, IP forwarding is enabled.  If native
apps mode is enabled for a host of type `switch`, then a special instance of
Open vSwitch is started in connection with the virtual host.  Finally, when
host of type `switch` is started, special environment variables are set with
its VLAN configuration (see [VLAN Attributes](#vlan-attributes)).


## Routes

The behavior resulting from setting the `routes` attributes depends on whether
a host or router has been configured for native apps (i.e., with the
`native_apps` configuration option).

A subtle behavior related to configuration is that only when the type is
`router` and native apps mode is in effect is IP forwarding enabled through the
router.


### Native Apps

In native apps mode, a [virtual host](#virtual-hosts) is created, the
forwarding rules are added using the `ip route` command.  Thus any packets sent
using the native network stack will use the table entries to determine which
interface should be used for an outgoing packet.


### Non-Native Apps

If forwarding rules are specified using the `routes` option for a host, then
the router is made aware of these rules via the environment variable
`COUGARNET_ROUTES`.  The value of this variable is a JSON list of three-tuples
(lists), each representing the prefix, outgoing interface, and next hop.  If
there is no next hop, then its value is `null`.

For example, consider the following configuration.

```
NODES
h1 routes=0.0.0.0/0|s1|10.0.0.1;10.0.2.0/24|s1|;::/0|s1|2001:db8::1;2001:db8:f00d::/64|s1|
s1

LINKS
h1,10.0.0.2/24,2001:db8::2/64 s1
```

In this case, `h1` has two IPv4 entries and two IPv6 entries, including a
default route for both IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`).  The entries for
`10.0.2.0/24` and `2001:db8:f00d::/64` have no next hop value.  The value of
the `COUGARNET_ROUTES` for `h1` will be the following:

```bash
COUGARNET_ROUTES=[["0.0.0.0/0", "h1-s1", "10.0.0.1"], ["10.0.2.0/24", "h1-s1", null], ["::/0", "h1-s1", "2001:db8::1"], ["2001:db8:f00d::/64", "h1-s1", null]]
```

These IP forwarding entries can be parsed using a JSON parser, such as with the
following Python code:

```python
import json
import os
import pprint

routes = json.loads(os.environ['COUGARNET_ROUTES'])
pprint.pprint(routes)
```

The corresponding output would be:

```
[['0.0.0.0/0', 'h1-s1', '10.0.0.1'],
 ['10.0.2.0/24', 'h1-s1', None],
 ['::/0', 'h1-s1', '2001:db8::1'],
 ['2001:db8:f00d::/64', 'h1-s1', None]]
```


## Environment

In the virtual host process, certain environment variables are set to help
processes running within the virtual host have better context of their network
environment.  All environment variables start with `COUGARNET_`.  The
environment variables currently defined are:

 - `COUGARNET_COMM_SOCK` and `COUGARNET_MY_SOCK`:
   described [here](#communicating-with-the-calling-process)
 - `COUGARNET_VLAN`:
   described [here](#vlan-attributes)
 - `COUGARNET_ROUTES`:
   described [here](#routes)

They can be retrieved from a running process in the standard way.  For example,
from command line:

```bash
$ echo $COUGARNET_COMM_SOCK
```

or from Python:

```python
#!/usr/bin/python3
import os
print(os.environ['COUGARNET_COMM_SOCK'])
```


## Running Programs

When a program is specified with the `prog` attribute, that program will be
executed in the virtual host.  Furthermore, programs from all virtual hosts are
intended to start at *approximately* the same time--though there is some
non-determinism as to their *exact* timing.

If `terminal` is enabled for a given host (the default), or the `--terminal`
option is used on the command line with either the name of the host or `all`,
then the program will have access to the standard input, standard output, and
standard error for a given host.

In either case (terminal or not), the program will have access to all the
[environment variables](#environment-variables) associated with the virtual
host.

Suppose `loop.sh` (in the current directory) contains the following:

```bash
#!/bin/bash
hostname
echo $COUGARNET_ROUTES
echo $1
for i in {1..3}; do
    echo $i
    sleep 1
done
```

And `cougarnet` is run with the following configuration:

```
NODES
h1 prog=./loop.sh|hello,routes=0.0.0.0/0|s1|10.0.0.4
```

The result would be the following:

```
h1
[["0.0.0.0/0", "h1-s1", "10.0.0.4"]]
hello
1
2
3
```

The equivalent Python code would be:

```python
#!/usr/bin/python3
import os
import socket
import sys
import time
print(socket.gethostname())
print(os.environ['COUGARNET_ROUTES'])
print(sys.argv[1])
for i in range(1, 4):
    print(i)
    time.sleep(1)
```

The output is the same as the previous output.


## Sending and Receiving Frames

When Cougarnet is used for protocol development, it is desirable to send and
receive raw Ethernet frames, rather than using the native network stack, i.e.,
with the socket API.  The `BaseHost` class is useful for sending and receiving
frames in Cougarnet.  The key components are the following:

 - `int_to_sock` - a `dict` containing a mapping of
   [interface names](#interface-names) to raw sockets (i.e., for sending
   frames).
 - `int_to_info` - a `dict` containing a mapping of
   [interface names](#interface-names) to `InterfaceInfo` instances.  An
   `InterfaceInfo` instance has the following attributes:
   - `mac_addr` - the MAC address for the interface.
   - `ipv4_addrs` - a list of IPv4 addresses with which the interface has been
     configured.  Please note that _typically_ an interface will just be configured
     with a single IP address.  Thus, usually `ipv4_addrs[0]` will work just fine.
   - `ipv4_prefix_len` - the length of the IPv4 prefix associated with this
     interface.
   - `ipv6_addrs` - a list of IPv6 addresses with which the interface has been
     configured.  Please note that just as with IPv4, an interface will typically
     just be configured with a single IP address.  Thus, usually `ipv6_addrs[0]`
     will work just fine.
   - `ipv6_addr_link_local` - the link-local IPv6 address with which the
     interface has been configured.
   - `ipv6_prefix_len` - the length of the IPv6 prefix associated with this
     interface.
   - `mtu` - the MTU of the link associated with the interface.
 - `hostname` - a `str` whose value is the [hostname](#hostnames) of the virtual host.
 - `comm_sock` - a socket (`socket.socket`) that is connected to the
   [communications socket](#communicating-with-the-calling-process) on which
   the calling `cougarnet` process is listening (i.e., for logging).
 - `get_interface()` - returns the name of one of the interfaces on the virtual
   host.  This can only be used when the device has just one interface.  It is
   intended to facilitate easy retrieval of the interface.
 - `send_frame(frame, intf)` - send frame (type `bytes`) out on the interface
   designated by name `intf`, a `str`.  Generally calling this method is
   preferred over calling `sendto()` on a socket  directly.
 - `log(msg)` - send message `msg` (type `str`) to the communications socket.
   Generally calling this method is preferred over calling `sendto()` on the
   communications socket (i.e., `comm_sock`) directly.

This is designed to provide a base class, which can be subclassed, such that
the inherited functionality is accessible to the child class.

The `BaseHost` class uses Python's `SelectorEventLoop`
[documentation](https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.SelectorEventLoop)
to handle incoming frames and scheduled events.  Every time an Ethernet frame
is received on an interface of the virtual host running the script, the
`_handle_frame()` method is called with the following arguments:

 - `frame` (type `bytes`) - the frame received; and
 - `intf` (type `str`) - the name of the interface out which it should be sent.

For example, consider the following code:

```python
import asyncio
from cougarnet.sim.host import BaseHost

class FramePrinter(BaseHost):
    def _handle_frame(self, frame, intf):
        self.log(f'Received frame on {intf}: {repr(frame)}')

def main():
    frame_printer = FramePrinter()
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    finally:
        loop.close()
```

With the above example, every time an Ethernet frame is received, a
representation of the frame and the name of the interface on which it was
received is sent to the calling process over the UNIX domain socket set up for
that purpose, with the `log()` method.  Of course, `_handle_frame()` can be
overridden to do whatever the developer would like; this is simply an example.


## Scheduling Events

Events (besides incoming packets) are added to the event loop by calling its
`call_later()` method.  For example:

```python
import asyncio

loop = asyncio.get_event_loop()
loop.call_later(1, do_something, arg1, arg2)
```

The `call_later()` method is documented
[here](https://docs.python.org/3/library/asyncio-eventloop.html#scheduling-delayed-callbacks).

For example, consider the following:

```python
import asyncio

loop = asyncio.get_event_loop()

def say_hello(arg):
    print(f'hello {arg}')

loop.call_later(2, say_hello, 'world')
loop.run_forever()
```

Assuming the event loop is running, this would result in "hello world" being
printed two seconds from the time `call_later()` was called.  A perpetual event
could happen by running the following:

```python
import asyncio

loop = asyncio.get_event_loop()

def say_hello(arg):
    print(f'hello {arg}')
    loop.call_later(2, say_hello, 'world')

loop.call_later(2, say_hello, 'world')
loop.run_forever()
```

This would result in `say_hello()` being called every two seconds.  Note that
is not a recursive call because `say_hello()` is not calling `say_hello()`; it
is simply scheduling `say_hello()` to be called later.


## Cancelling Events

When an event is scheduled by calling `call_later()`, an `asyncio.TimerHandle`
instance is returned.  The event can be cancelled by calling `cancel()` on that
instance. For example:

```python
import asyncio

loop = asyncio.get_event_loop()

def say_hello(arg):
    print(f'hello {arg}')

event = loop.call_later(2, say_hello, 'world')
event.cancel()
loop.run_forever()
```

The call to `say_hello()` is cancelled before it ever gets run!


# Virtual Links

Virtual links are created between two virtual interfaces with the `ip link`
command, using type `veth`: such that one virtual interface is associated with
one network namespace and the second is associated with another network
namespace.  Those two namespaces are the two associated with two processes
 that are running in their own namespaces.  These processes, of course, are
[virtual hosts](#virtual-hosts), so these virtual links become the basis for
connections between virtual hosts.


## Configuration

In the Cougarnet configuration file, a link between two hosts is designated in
the `LINKS` section by indicating two hosts on a line, separated by a space.
Consider the `LINKS` section of the [example configuration given
previously](#getting-started):

```
LINKS
h1,10.0.0.1/24 h2,10.0.0.2/24
```

This results in a virtual interface being created for each virtual host.  More
on per-host interface naming can be found [here](#interface-names).


### Addressing

Each interface can be configured with zero or more addresses, up to one MAC
address and zero or more IPv4 and/or IPv6 addresses.  The list of addresses is
comma-separated.  For example, we might like to configure the `h1` and  `h2`
virtual interfaces thus:

```
LINKS
h1,00:00:aa:aa:aa:aa,10.0.0.1/24,fd00::1/64 h2,10.0.0.2/24,fd00::2/64
```

In this case, `h1`'s virtual network interface will not only have IPv4 address
10.0.0.1, but also MAC address 00:00:aa:aa:aa:aa and IPv6 address fd00::1/64.
Likewise, `h2`'s virtual network interface will have IPv6 address fd00::2/64,
in addition to IPv4 address 10.0.0.2.


### Additional Options

Additional options can be specified for any link.  For example, we might like
to provide the (original) link between `h1` and `h2` with additional
configuration, such as the following:

```
LINKS
h1,10.0.0.1/24 h2,10.0.0.2/24 bw=1Mbps,delay=20ms,loss=10%
```

In this case, the bandwidth of the link will be 1Mbps, instead of the default
10Gbps, an artificial delay of 20 ms will be applied to any packet crossing the
link, and an artificial packet loss rate of 10% will be applied to packets
crossing the link.  That is, any packet has a 10% chance of being dropped.

In general, the syntax for a link is:

```
<hostname>[,<addr>[,<addr>...]] <hostname>[,<addr>[,<addr>...]] [name=val[,name=val[...]]
```

That is, if there are additional options, there is a space after the interface
information for the second host, and those options come after the space. The
options consist a comma-delimited list of name-value pairs, each name-value
connected by `=`.  The defined link option names are the following, accompanied
by the expected value:
 - `bw`:  an artificial bandwith to apply to the link.  Example: `1Mbps`.
   Default: `10Gbps`.
 - `delay`: an artificial delay to be added to all packets on the link.
   Example: `50ms`.  Default: no delay.
 - `loss`: an average rate of artificial loss that should be applied
   to the link.  Example: `10%`.  Default: no loss.
 - `mtu`: the number of bytes associated with the maximum transmission unit
   (MTU).  Example: `500`.  Default: `1500`.
 - `vlan`: the VLAN id (integer with value 0 through 1023) associated with the
   link.  Example: `20`.  Default: no VLAN id.  See [VLAN
   Attributes](#vlan-attributes) for more information.
 - `trunk`: a boolean (i.e., `true` or `false`) indicating whether this link
   should be a trunk link between two switches, such that 802.1Q frames are
   passed on that link.  Default: `false`.  See [VLAN
   Attributes](#vlan-attributes) for more information.

Note that for a given switch, one of the following must be true:
 - all interfaces must be either trunked (i.e., `trunk=true`) or have a
   designated VLAN (e.g., `vlan=10`); or
 - no interfaces must be trunked or have a designated VLAN.

The former case is a more modern example of a switch, where VLANs are the norm,
and the latter is an example of a simple switch.

Additionally, a switch interface cannot be assigned to both a VLAN and to a
trunk.


## Bi-Directionality of Link Attributes

A note about the link-specific attributes.  They are applied in both
directions.  Thus, using the example configuration above, running a `ping`
command between `h1` and `h2` will result in something like this:

```
h2$ ping -c 10 h1
PING h1 (10.0.0.1) 56(84) bytes of data.
64 bytes from h1 (10.0.0.1): icmp_seq=2 ttl=64 time=41.5 ms
64 bytes from h1 (10.0.0.1): icmp_seq=4 ttl=64 time=41.3 ms
64 bytes from h1 (10.0.0.1): icmp_seq=5 ttl=64 time=41.1 ms
64 bytes from h1 (10.0.0.1): icmp_seq=6 ttl=64 time=40.8 ms
64 bytes from h1 (10.0.0.1): icmp_seq=7 ttl=64 time=40.8 ms
64 bytes from h1 (10.0.0.1): icmp_seq=8 ttl=64 time=41.8 ms
64 bytes from h1 (10.0.0.1): icmp_seq=9 ttl=64 time=41.4 ms
64 bytes from h1 (10.0.0.1): icmp_seq=10 ttl=64 time=41.3 ms

--- h1 ping statistics ---
10 packets transmitted, 8 received, 20% packet loss, time 9061ms
rtt min/avg/max/mdev = 40.811/41.242/41.775/0.306 ms
```

Note that the round-trip time (RTT) was consistently around just over 40 ms
(i.e., 20 ms for the ICMP request and 20 ms for the ICMP response).  Also, any
packet has a 10% chance of being lost.  Because a successful `ping` requires
the successful transmission of both an ICMP request and the corresponding ICMP
response, the chance of success is 81%:

```
P(success)
  = P(neither pkt is lost)
  = (1 - P(loss)) * (1 - P(loss))
  = (1 - 0.10) * (1 - 0.10)
  = 0.81
```

In other words, 1 in 5 ICMP request messages sent will not result in an ICMP
response message received.  In the example above, `ping` messages with id
numbers 1 and 3 were unsuccessful.


## VLAN Attributes

The behavior resulting from setting the `vlan` and `trunk` attributes depends
on whether a switch has been configured for native apps (i.e., with the
`native_apps` configuration option).

In either case, neither the `vlan` attribute nor the `trunk` attribute have any
effect unless at least one of the hosts is of type `switch`.


### Native Apps
In native apps mode, a virtual switch is created (using Open vSwitch), and the
links are assigned as designated VLAN or trunk links, respectively.


### Non-Native Apps
In non-native apps mode, the `COUGARNET_VLAN` environment variable contains the
VLAN information for each switch interface.

For example, consider the following configuration.

```
NODES
h1
h2 type=switch
h3
h4 type=switch

LINKS
h1 h2 vlan=25
h2 h3 vlan=32
h2 h4 trunk=true
```

In this case, `h2` and `h3` are each switches, connected by a trunk.  Both `h1`
and `h3` are connected to `h2`, with their links having VLAN assignments 25 and
32, respectively.  The link between `h2` and `h4` is a trunk.

In the process associated with `h2`, the environment variable `COUGARNET_VLAN`
contains a JSON object mapping each interface to its VLAN or trunk assignment.
The value for an interface assigned to a VLAN has the form `vlan<id>` where
`<id>` is the numerical VLAN id.  The value for an interface that corresponds
to a trunk link is simply `trunk`.  The above configuration would result in the
following environment variable being set for `h2`:

```bash
COUGARNET_VLAN={"h2-h1": "vlan25", "h2-h3": "vlan32", "h2-h4": "trunk"}
```

and the following set for `h4`:

```bash
COUGARNET_VLAN={"h4-h2": "trunk"}
```

These VLAN assignments can be parsed using a JSON parser, such as with the
following Python code:

```python
import json
import os
import pprint

vlan_info = json.loads(os.environ['COUGARNET_VLAN'])
pprint.pprint(vlan_info)
```

The corresponding output would be:

```
{'s1-a': 'vlan25', 's1-b': 'vlan25', 's1-c': 'vlan30', 's1-s2': 'trunk'}
```


# Network Configuration File

The full syntax for the network configuration file is as follows:

```
HOSTS
[<hostname> [name=val[,name=val[...]]]
[...]

LINKS
[<hostname>[,<addr>[,<addr>...]] <hostname>[,<addr>[,<addr>...]] [name=val[,name=val[...]]]
[...]
```

Blank links and lines beginning with `#` (i.e., comments) are ignored.

See specifics in the [virtual host](#configuration) and [virtual
link](#configuration-1) configuration sections.


# Command-Line Usage

```
$ cougarnet --help
usage: cougarnet [-h] [--wireshark NODE] [--display] [--vars VARS] [--terminal TERMINAL] [--disable-ipv6] [--native-apps {all,none}]
                 [--display-file DISPLAY_FILE]
                 config_file

positional arguments:
  config_file           File containing the network configuration

optional arguments:
  -h, --help            show this help message and exit
  --wireshark NODE, -w NODE
                        Start wireshark for the specified links (host1-host2[,host2-host3,...])
  --display             Display the network configuration as text
  --vars VARS           Specify variables to be replaced in the configuration file (name=value[,name=value,...])
  --terminal TERMINAL   Specify which virtual hosts should launch a terminal (all|none|host1[,host2,...])
  --disable-ipv6        Disable IPv6
  --native-apps {all,none}
                        Specify that all virtual hosts should enable (all) or disable (none) native apps.
  --display-file DISPLAY_FILE
                        Print the network configuration to a file (.png)
```

Note that `--terminal` overrides all per-host `terminal` options.

Also note that the `--display-file` option is not yet fully-functional.
