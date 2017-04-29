META-DATA(8) - System Manager's Manual

# NAME

**meta-data** - meta-data server for OpenBSD's virtual machine daemon

# SYNOPSIS

**meta-data**
\[**-23**]
\[**-u**&nbsp;*user*]
\[**-l**&nbsp;*lease-file*]
\[*bridge*]

# DESCRIPTION

The
**meta-data**
FastCGI program provides a cloud-init datasource for
OpenBSD's
vmd(8)
that is compatible with Apache CloudStack
and partially compatible with Amazon EC2.

The options are as follows:

**-2**

> Run in layer
> **2**
> mode.
> **meta-data**
> will find the guest VM by its MAC address in the DHCP
> *lease-file*
> and the
> *bridge*
> cache.
> This is the default if layer
> **3**
> mode is not specified.
> The default bridge name is
> "bridge0".

**-3**

> Run in layer
> **3**
> mode.
> **meta-data**
> will find the guest VM by its IPv4 address in the ARP table.
> The layer
> **2**
> and
> **3**
> modes can be combined.

**-u** *user*

> Change the
> *user*
> name.
> The default is
> "\_meta-data".

**-l** *lease-file*

> Change the
> *lease-file*.
> The default is
> */var/db/dhcpd.leases*.

Use the following steps to run
**meta-data**:

1.	Create the
	*meta-data*
	directory and add the
	"\_meta-data"
	user:

		# mkdir -p /home/vm/meta-data
		# groupadd -g 787 _meta-data
		# useradd -g 787 -u 787 -k /var/empty -d /home/vm/meta-data \
			-s /sbin/nologin -c "meta-data user" _meta-data

2.	Use the
	kfcgi(8)
	FastCGI server to run
	**meta-data**.
	Start it as root, with chroot disabled, and
	**meta-data**
	will drop privileges by itself.
	The
	**meta-data**
	socket has to be owned by the "www" user of the web server.

		# kfcgi -r -n 2 -u www -p / -- /usr/local/libexec/meta-data

3.	Configure and start
	httpd(8)
	to handle
	**meta-data**
	requests:

		server "meta-data" {
			listen on 169.254.169.254 port 80
			fastcgi socket "/run/httpd.sock"
			root { "/", strip 1 }
		}

# ATTRIBUTES

**meta-data**
serves a number of attributes, so-called meta-data items and optional
user-data, that are specific to the requesting VM.
The following attributes are supported:

**meta-data/availability-zone**

> This option is provided for compatibility.
> It includes the name of the
> *bridge*
> interface.

**meta-data/instance-id**

> The VM identifier in the format
> **vm**&zwnj;*ID*,
> e.g.
> *vm1*.

**meta-data/local-hostname**

> The hostname of the guest VM,
> based on the VM name that was specified in
> vm.conf(5)
> or by the
> vmctl(8)
> **start**
> command.

**meta-data/local-ipv4**

> The IPv4 address of the guest VM.
> It is identical to the verified guest IP address of the HTTP request.

**meta-data/public-hostname**

> This option is provided for compatibility.
> It includes the hostname of the
> vmd(8)
> host where
> **meta-data**
> is running.

**meta-data/public-ipv4**

> This option is provided for compatibility.
> It currently includes the fixed string
> "127.0.0.1".

**meta-data/public-keys/0/openssh-key**

> The SSH public key that is included in the
> *openssh-key*
> file in the VM's configuration directory.
> See the
> *FILES*
> section below.
> **meta-data**
> returns an
> "HTTP 404 Not Found"
> error if the file does not exist.

**meta-data/service-offering**

> This option is provided for compatibility.
> It includes the fixed string
> "OpenBSD".

**meta-data/username**

> Returns the contents of the
> *username*
> file in the VM's configuration directory,
> or
> "root"
> if it does not exist.
> This item is not available in other meta-data implementations.

**user-data**

> Returns the contents of the
> *user-data*
> file in the VM's configuration directory,
> or an
> "HTTP 404 Not Found"
> if it does not exist.
> The user-data file typically includes a configuration file or shell
> script of a type that is indicated by the
> "shebang"
> in the first line, for example
> "#!/bin/sh"
> or
> "#cloud-config".

# FILES

*/home/vm/meta-data/openbsd.vm*

> Directory containing meta-data for the virtual machine
> "openbsd.vm".

*openssh-key*

> The SSH public key in the VM's meta-data directory.

*user-data*

> "user-data" file in the VM's meta-data directory.

*username*

> The login username (this is an extension).

# SEE ALSO

kcgi(8),
kfcgi(8),
vmd(8)

*User-Data and Meta-Data*,
[http://docs.cloudstack.apache.org/projects/cloudstack-administration/en/latest/virtual\_machines.html#user-data-and-meta-data](http://docs.cloudstack.apache.org/projects/cloudstack-administration/en/latest/virtual_machines.html#user-data-and-meta-data).

# AUTHORS

Reyk Floeter &lt;[reyk@openbsd.org](mailto:reyk@openbsd.org)&gt;

OpenBSD 6.1 - April 29, 2017
