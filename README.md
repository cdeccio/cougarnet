# Cougarnet

Cougarnet creates a virtual network for learning network configuration and
protocols.  It takes as input a [network configuration
file](#network-configuration-file).  Using the configuration as a guide, it
creates [virtual hosts](#virtual-hosts) and [virtual links](#virtual-links)
between them.  It can also add MAC and IP address information to interfaces,
specify [bandwidth](#link-bandwidth), (propagation) [delay](#link-delay), or
[loss](#link-loss) to links.

Perhaps the most power feature of Cougarnet is the ability to either use the
built-in Linux network stack or capture raw frames only.  The former is useful
for configuring and using a network with built-in tools (e.g., ping,
traceroute), while the latter is useful for implementing the protocol stack in
software.  Additionally, there can be a mixture--some hosts that use native
stack and some that do not.


# Installation

To install Cougarnet, run the following:

```
$ python setup.py build
$ sudo python setup.py install
```

TODO: `sudo`, `wireshark`, `lxde-terminal`


# Getting Started

To get started, create a simple network configuration.  Create a file called
`simple-net.cfg` with the following contents:

```
NODES
h1
h2

LINKS
h1,10.0.0.1/24 h2,10.0.0.2/24
```

This simple configuration results in a network composed of two nodes, named
`h1` and `h2`.  There is a single link between them.  For the link between `h1`
and `h2`, `h1`'s interface will have an IPv4 address of 10.0.0.1, and `h2` will
have an IPv4 address of 10.0.0.2.  The `/24` indicates that the length of the
IPv4 prefix associated with that link is 24 bit associated with that link is 24
bits, i.e., 10.0.0.0/24.

Start Cougarnet with this configuration by running the following command:

```
cougarnet simple-net.cfg
```

When it starts up, it will launch two new terminals.  One will be associated
with the virtual host `h1` and the other with `h2`.  The prompt at each should
indicate which is which.

Each each terminal, run the following to see the network configuration:
```
$ ip addr
```
Note first that each virtual host sees only its own interface. Also note that
each host is configured with the address from the configuration file.

Next, from the `h2` terminal, run the following:

```
h2$ sudo tcpdump -l
```
(Note that in this example and elsewhere in this document `h2$` simply
indicates that it is the prompt corresponding to `h2`.)

The `-l` option to `tcpdump` ensures that line-based buffering is used, so the
output is printed as soon as it is generated.

Now from the `h1` terminal, run the following:

```
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


## Communicating with the Calling Process

Often it is useful for the virtual host to send messages back to the process
that invoked all the virtual hosts (i.e., the `cougarnet` process).  This
enables the logs for all messages to be received and printed in a single
location.  To accomplish this, each virtual process has the
`COUGARNET_COMM_SOCK`  environment variable set, the value of which is a path
corresponding to a Unix domain socket (i.e., family `AF_UNIX`) of type
`SOCK_DGRAM`.  Once all the virtual machines are started, the `cougarnet`
process will print to standard output all messages received on this socket.

For example, the following command, issued from a virtual host, will result in
a UDP datagram being sent to the UNIX domain socket on which the `cougarnet`
process is listening.

```
echo -n `hostname`,hello world | socat - UNIX-SENDTO:$COUGARNET_COMM_SOCK
```

The equivalent Python code is the following:

```
import os
import socket

sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
sock.connect(os.environ['COUGARNET_COMM_SOCK'])
hostname = socket.gethostname()
sock.send(f'{hostname},hello world'.encode('utf-8'))
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
   was sent.  Note that the hostname must be sent by the virtual host.  It is
   done by prepending the hostname, separating it from the actual message with
   a comma.  Thus, the following message in the previous example:
   ```
   echo -n `hostname`,hello world
   ```
 - *Message* (`hello world`): the actual message to be logged and/or printed.

The `rawpkt.BaseFrameHandler` has a function `log()` which can be used to issue
messages.  So if you subclass `rawpkt.BaseFrameHandler` and then call `log()`,
it will handle the formatting for you.

TODO: more on this BaseFrameHandler below.  For an example, refer to
BaseFrameHandler documentation.

## Configuration

In the Cougarnet configuration file, additional options can be specified for a
given host.  Consider the `NODES` section of the [example configuration given
previously](#getting-started):

```
NODES
h1
h2
```

We might like to provide `h1` with additional configuration, such as the
following:

```
NODES
h1 gw4=10.0.0.4,terminal=false
h2
```

In general, the syntax for a host is:

```
<hostname> [name=val,[name=val,...]]
```

That is, if there are additional attributes, they come after a space following
the hostname and consist of a comma-delimited list of name-value pairs.  The
defined host attribute names are the following, accompanied by the expected
value:
 - *gw4*: an IPv4 address representing the gateway or default router.  Default:
   no IPv4 gateway.
 - *gw6*: an IPv6 address representing the gateway or default router.  Default:
   no IPv6 gateway.
 - *native_apps*: a boolean (i.e., `true` or `false`) indicating whether or the
   native network stack should be used.  Default: `true`.
 - *terminal*: a boolean (i.e., `true` or `false`) whether a terminal should be
   spawned (TODO: reference the terminal section).  Default: `true`.


# Virtual Links

