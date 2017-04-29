/*
 * Copyright (c) 2017 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_bridge.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <errno.h>
#include <err.h>

#include <kcgi.h>
#include <kcgihtml.h>

#define LEASE_FILE	"/var/db/dhcpd.leases"
#define BRIDGE_NAME	"bridge0"
#define DATA_USER	"_meta-data"

struct lease {
	struct ether_addr	 l_lladdr;
	struct in_addr		 l_ipaddr;
	TAILQ_ENTRY(lease)	 l_entry;
};
TAILQ_HEAD(leases, lease);

struct metadata {
	struct kreq		 env_r;

	const char		*env_bridge;
	const char		*env_lease_file;
	const char		*env_data_user;
	int			 env_l2;
	int			 env_l3;

	FILE			*env_leasefp;
	struct leases		 env_leases;
	int			 env_ioctlfd;
};

struct vm {
	struct in_addr		 vm_ipaddr;
	struct lease		*vm_lease;
	char			 vm_ifname[IFNAMSIZ];
	char			 vm_ifdescr[IFDESCRSIZE];
	char			*vm_instance_id;
	char			*vm_interface_name;
	char			*vm_local_hostname;
};

enum pageids {
	PAGE_INDEX,
	PAGE_META_DATA,
	PAGE_USER_DATA,
	PAGE__MAX
};

const char *pagenames[PAGE__MAX] = {
	".",
	"meta-data",
	"user-data"
};

void	 page_home(struct metadata *, struct vm *);
void	 page_index(struct metadata *, const char *names[], size_t);
int	 page_file_data(struct metadata *, struct vm *vm, const char *);
void	 page_meta_data(struct metadata *, struct vm *);
void	 page_user_data(struct metadata *, struct vm *);
void	 page_error(struct metadata *, int);

char	*parse_value(const char *, char *);
void	 parse_leases(struct metadata *);
void	 free_leases(struct metadata *);
struct lease *
	 find_lease(struct metadata *, struct vm *);

int	 find_l2(struct metadata *, struct vm *);
int	 find_l3(struct metadata *, struct vm *);
int	 find_vm(struct metadata *, struct vm *);

__dead void usage(void);

struct page {
	enum pageids	 page_id;
	void		(*page_cb)(struct metadata *, struct vm *);
} pages[] = {
	{ PAGE_INDEX,		page_home },
	{ PAGE_META_DATA,	page_meta_data },
	{ PAGE_USER_DATA,	page_user_data },
	{ PAGE__MAX,		page_home },
};

char *
parse_value(const char *s1, char *s2)
{
	size_t	 len = strlen(s1);
	char	*v;

	if (strncmp(s1, s2, len) != 0)
		return (NULL);

	v = s2 + len;
	v[strcspn(v, " \t\r\n;{}\0")] = '\0';

	return (v);
}

void
parse_leases(struct metadata *env)
{
	char		 buf[BUFSIZ], *k, *v;
	struct lease	*l = NULL;

	TAILQ_INIT(&env->env_leases);

	if (fseek(env->env_leasefp, 0, SEEK_SET) == -1)
		err(1, "can't rewind lease file");

	while (fgets(buf, sizeof(buf), env->env_leasefp) != NULL) {
		k = buf + strspn(buf, " \t");

		if ((v = parse_value("lease ", k)) != NULL) {
			if ((l = calloc(1, sizeof(*l))) == NULL)
				err(1, "cannot add lease");

			inet_pton(AF_INET, v, &l->l_ipaddr);

			/* insert in reverse order */
			TAILQ_INSERT_HEAD(&env->env_leases, l, l_entry);
		} else if ((v =
		    parse_value("hardware ethernet ", k)) != NULL) {
			if (l == NULL)
				err(1, "syntax error");
			l->l_lladdr = *ether_aton(v);
		}
	}
}

void
free_leases(struct metadata *env)
{
	struct lease	*l, *next;

	TAILQ_FOREACH_SAFE(l, &env->env_leases, l_entry, next) {
		TAILQ_REMOVE(&env->env_leases, l, l_entry);
		free(l);
	}
}

struct lease *
find_lease(struct metadata *env, struct vm *vm)
{
	struct lease	*l;

	TAILQ_FOREACH(l, &env->env_leases, l_entry) {
		if (vm->vm_ipaddr.s_addr == l->l_ipaddr.s_addr) {
			vm->vm_lease = l;
			return (l);
		}
	}

	return (NULL);
}

/*
 * Find the VM's name interface using a simple trick:
 * - find the MAC by searching for the client's IP in the lease database
 * - locate the VM's tap interface on the bridge that matches the MAC
 * - get the tap interface description which encodes the VM id and name
 *
 * XXX This is a "hack" and will be replaced in the future when I fixed vmd:
 * XXX - provide a control imsg in vmd to find a VM by MAC
 */
int
find_l2(struct metadata *env, struct vm *vm)
{
	struct ifbaconf	 ifbac;
	struct ifbareq	*ifba;
	char		*inbuf = NULL, *p;
	struct lease	*l = vm->vm_lease;
	int		 ret = -1;
	size_t		 i, len = BUFSIZ;

	for (;;) {
		ifbac.ifbac_len = len;
		if ((p = realloc(inbuf, len)) == NULL)
			err(1, "malloc");
		ifbac.ifbac_buf = inbuf = p;
		strlcpy(ifbac.ifbac_name, env->env_bridge,
		    sizeof(ifbac.ifbac_name));
		if (ioctl(env->env_ioctlfd, SIOCBRDGRTS, &ifbac) < 0) {
			if (errno == ENETDOWN)
				return (-1);
			err(1, "%s", env->env_bridge);
		}
		if (ifbac.ifbac_len + sizeof(*ifba) < len)
			break;
		len *= 2;
	}

	for (i = 0; i < ifbac.ifbac_len / sizeof(*ifba); i++) {
		ifba = ifbac.ifbac_req + i;

		if (memcmp(&ifba->ifba_dst, &l->l_lladdr,
		    sizeof(l->l_lladdr)) == 0) {
			strlcpy(vm->vm_ifname, ifba->ifba_ifsname,
			    sizeof(vm->vm_ifname));
			ret = 0;
			break;
		}
	}
	free(inbuf);

	return (ret);
}

int
find_l3(struct metadata *env, struct vm *vm)
{
	int			 mib[] = {
	    CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO, 0
	};
	int			 mcnt = sizeof(mib) / sizeof(mib[0]);
	size_t			 sz;
	char			*end, *nbuf, *buf = NULL, *next;
	struct rt_msghdr	*rtm;
	struct sockaddr_inarp	*sin;
	struct sockaddr_dl	*sdl;
	int			 ret = -1;

	for (;;) {
		if (sysctl(mib, mcnt, buf, &sz, NULL, 0) == -1)
			goto done;
		if ((nbuf = realloc(buf, sz)) == NULL)
			err(1, "realloc");
		buf = nbuf;
		if (sysctl(mib, mcnt, buf, &sz, NULL, 0) == -1) {
			if (errno == ENOMEM)
				continue;
			goto done;
		}
		end = buf + sz;
		break;
	}

	for (next = buf; next < end; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		sin = (struct sockaddr_inarp *)(next + rtm->rtm_hdrlen);
		sdl = (struct sockaddr_dl *)(sin + 1);
		if (vm->vm_ipaddr.s_addr == sin->sin_addr.s_addr &&
		    if_indextoname(sdl->sdl_index,
		    (char *)vm->vm_ifname) != NULL) {
			ret = 0;
			break;
		}
	}

	errno = ENOENT;
 done:
	free(buf);
	return (ret);
}

int
find_vm(struct metadata *env, struct vm *vm)
{
	struct ifreq	 ifr;
	char		*p;
	int		 found = -1;
	int		 ret = -1;

	/* First try to VM via L2 lookup in DHCP/bridge */
	if (env->env_l2) {
		parse_leases(env);
		if (find_lease(env, vm) != NULL)
			found = find_l2(env, vm);
	}

	/* Now try a L3 ARP lookup */
	if (env->env_l3 && found == -1)
		found = find_l3(env, vm);

	if (found == -1)
		goto done;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, vm->vm_ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&vm->vm_ifdescr;

	if (ioctl(env->env_ioctlfd, SIOCGIFDESCR, &ifr) == 0 &&
	    strlen(ifr.ifr_data)) {
		vm->vm_instance_id = p = vm->vm_ifdescr;
		if ((p = strchr(p, '-')) != NULL) {
			*p++ = '\0';
			vm->vm_interface_name = p;
		}
		if (p != NULL &&
		    (p = strchr(p, '-')) != NULL) {
			*p++ = '\0';
			vm->vm_local_hostname = p;
		}
	}
	if (vm->vm_local_hostname == NULL)
		goto done;

	ret = 0;
 done:
	if (env->env_leasefp != NULL)
		free_leases(env);
	return (ret);
}

void
page_index(struct metadata *env, const char *names[], size_t namesz)
{
	struct kreq	*r = &env->env_r;
	size_t		 i;

	khttp_head(r, kresps[KRESP_STATUS], "%s", khttps[KHTTP_200]);
	khttp_head(r, kresps[KRESP_CONTENT_TYPE],
	    "%s", kmimetypes[KMIME_TEXT_PLAIN]);
	khttp_body(r);

	for (i = 0; i < namesz; i++) {
		khttp_puts(r, names[i]);
		khttp_puts(r, "\n");
	}
}

void
page_home(struct metadata *env, struct vm *vm)
{
	page_index(env, pagenames, PAGE__MAX);
}

int
page_file_data(struct metadata *env, struct vm *vm, const char *name)
{
	struct kreq	*r = &env->env_r;
	char		 path[PATH_MAX], buf[BUFSIZ];
	FILE		*fp = NULL;
	size_t		 len;

	snprintf(path, sizeof(path), "%s/%s",
	    vm->vm_local_hostname, name);
	if ((fp = fopen(path, "r")) == NULL)
		return (-1);

	khttp_head(r, kresps[KRESP_STATUS], "%s", khttps[KHTTP_200]);
	khttp_head(r, kresps[KRESP_CONTENT_TYPE],
	    "%s", kmimetypes[KMIME_TEXT_PLAIN]);
	khttp_body(r);
	do {
		if ((len = fread(buf, 1, sizeof(buf), fp)) == 0)
			break;
		khttp_write(r, buf, len);
	} while (len == sizeof(buf));
	fclose(fp);

	return (0);
}

void
page_meta_data(struct metadata *env, struct vm *vm)
{
	struct kreq	*r = &env->env_r;
	const char	*str = NULL;
	struct lease	*l = vm->vm_lease;
	char		 hostname[NI_MAXHOST];
	enum		 dataids {
		D_SERVICE_OFFERING,
		D_AVAILABILITY_ZONE,
		D_LOCAL_IPV4,
		D_LOCAL_HOSTNAME,
		D_PUBLIC_IPV4,
		D_PUBLIC_HOSTNAME,
		D_INSTANCE_ID,
		D_OPENSSH_KEY,
		D_USERNAME,
		D__MAX
	};
	const char	*datanames[] = {
		"service-offering",
		"availability-zone",
		"local-ipv4",
		"local-hostname",
		"public-ipv4",
		"public-hostname",
		"instance-id",
		"public-keys/",
		"username"
	};

	/* Directory listing */
	if (*r->path == '\0') {
		page_index(env, datanames, D__MAX);
		return;
	}

	/* Supported options */
	else if (strcmp(datanames[D_LOCAL_HOSTNAME], r->path) == 0)
		str = vm->vm_local_hostname;
	else if (strcmp(datanames[D_LOCAL_IPV4], r->path) == 0)
		str = inet_ntoa(l->l_ipaddr);
	else if (strncmp(datanames[D_OPENSSH_KEY], r->path,
	    strlen(datanames[D_OPENSSH_KEY])) == 0) {
		if (strcmp(datanames[D_OPENSSH_KEY], r->path) == 0) {
			str = "0=mykey";
		} else {
			if (page_file_data(env, vm, "openssh-key") == -1)
				page_error(env, KHTTP_404);
			return;
		}
	} else if (strcmp(datanames[D_INSTANCE_ID], r->path) == 0)
		str = vm->vm_instance_id;

	/* non-standard extensions */
	else if (strcmp(datanames[D_USERNAME], r->path) == 0) {
		if (page_file_data(env, vm, "username") == 0)
			return;
		str = "root";
	}

	/* The following values are just "faked" for compatibility */
	else if (strcmp(datanames[D_PUBLIC_HOSTNAME], r->path) == 0) {
		gethostname(hostname, sizeof(hostname));
		str = hostname;
	} else if (strcmp(datanames[D_PUBLIC_IPV4], r->path) == 0)
		str = "127.0.0.1"; /* XXX */
	else if (strcmp(datanames[D_AVAILABILITY_ZONE], r->path) == 0)
		str = env->env_bridge; /* XXX */
	else if (strcmp(datanames[D_SERVICE_OFFERING], r->path) == 0)
		str = "OpenBSD"; /* XXX */

	if (str == NULL) {
		page_error(env, KHTTP_404);
		return;
	}

	khttp_head(r, kresps[KRESP_STATUS], "%s", khttps[KHTTP_200]);
	khttp_head(r, kresps[KRESP_CONTENT_TYPE],
	    "%s", kmimetypes[KMIME_TEXT_PLAIN]);
	khttp_body(r);
	khttp_puts(r, str);
}

void
page_user_data(struct metadata *env, struct vm *vm)
{
	if (page_file_data(env, vm, "user-data") == -1)
		page_error(env, KHTTP_404);
}

void
page_error(struct metadata *env, int code)
{
	struct kreq	*r = &env->env_r;
	khttp_head(r, kresps[KRESP_STATUS], "%s", khttps[code]);
	khttp_head(r, kresps[KRESP_CONTENT_TYPE],
	    "%s", kmimetypes[KMIME_TEXT_PLAIN]);
	khttp_body(r);
	khttp_puts(r, khttps[code]);
}

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-23] [-u user] [-l lease-file]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct metadata	 env;
	struct kreq	*r;
	struct kfcgi	*fcgi;
	struct page	*p = NULL;
	struct vm	 vm;
	size_t		 i;
	int		 valid;
	void		(*cb)(struct metadata *, struct vm *);
	struct passwd	*pw;
	int		 ch;

	memset(&env, 0, sizeof(env));
	env.env_bridge = BRIDGE_NAME;
	env.env_lease_file = LEASE_FILE;
	env.env_data_user = DATA_USER;
	env.env_ioctlfd = -1;

	while ((ch = getopt(argc, argv, "23l:u:")) != -1) {
		switch (ch) {
		case '2':
			env.env_l2 = 1;
			break;
		case '3':
			env.env_l3 = 1;
			break;
		case 'l':
			env.env_lease_file = optarg;
			env.env_l2 = 1;
			break;
		case 'u':
			env.env_data_user = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 1) {
		env.env_bridge = argv[1];
		env.env_l2 = 1;
	}

	/* Default to L2 mode */
	if (!env.env_l3)
		env.env_l2 = 1;

	/* Try to open dhcpd's lease file */
	if ((env.env_l2) &&
	    (env.env_leasefp = fopen(env.env_lease_file, "r")) == NULL)
		err(1, "can't open lease file");

	if ((pw = getpwnam(env.env_data_user)) == NULL)
		err(1, "can't get user");

	if (chroot(pw->pw_dir) == -1)
		err(1, "chroot");
	if (chdir("/") == -1)
		err(1, "chdir(\"/\")");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		err(1, "cannot drop privileges");

	if ((env.env_ioctlfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "can't open ioctl socket");

	if (khttp_fcgi_init(&fcgi, NULL, 0,
	    pagenames, PAGE__MAX, 0) != KCGI_OK)
		errx(1, "khttp_fcgi_init");

#if 0
	/*
	 * XXX The bridge ioctl prevents us from doing pledge(2) in
	 * XXX the main process (kcgi's parser still runs under pledge),
	 * XXX it can be turned on after switching from ioctl to an imsg
	 * XXX with vmd.
	 */
	if (pledge("stdio recvfd tty route", NULL) == -1)
		err(1, "pledge");
#endif

	r = &env.env_r;
	while (khttp_fcgi_parse(fcgi, r) == KCGI_OK) {
		memset(&vm, 0, sizeof(vm));
		valid = inet_pton(AF_INET, r->remote, &vm.vm_ipaddr);

		for (i = 0, cb = NULL; valid > 0 && i < PAGE__MAX; i++) {
			p = &pages[i];
			if (p->page_id == r->page) {
				cb = p->page_cb;
				break;
			}
		}

		if (valid <= 0)
			page_error(&env, KHTTP_401);
		else if (cb == NULL)
			page_error(&env, KHTTP_404);
		else {
			if (find_vm(&env, &vm) == -1)
				page_error(&env, KHTTP_404);
			else
				(*cb)(&env, &vm);
		}

		khttp_free(r);
	}

	khttp_fcgi_free(fcgi);
	if (env.env_leasefp != NULL)
		fclose(env.env_leasefp);
	if (env.env_ioctlfd != -1)
		close(env.env_ioctlfd);

	return (EXIT_SUCCESS);
}
