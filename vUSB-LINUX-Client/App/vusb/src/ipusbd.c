/*
* usbredir : vanxum vUSB used for usb device redirect
* Author : zhangzhiyong <zhangzhiyong@vanxum.com>
 */

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include<string.h>
#include<pthread.h>
#include<signal.h>
#include <sys/prctl.h>
#include<sys/wait.h>
#include <pthread.h>  
#include <stdio.h>  
#include <syslog.h>  
#include <stdbool.h>
#include <stdint.h>
#include <getopt.h>
#include <fcntl.h> // for open
#include "../libsrc/ipusb_common.h"
#include "ipusb_network.h"
#include "ipusb.h"
#include <sysfs/libsysfs.h>
#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#endif
#define _GNU_SOURCE
#include "../libsrc/ipusb_host_driver.h"
#undef  PROGNAME
#define PROGNAME "ipusbd"
#define MAXSOCKFD 20

enum unbind_status {
	UNBIND_ST_OK,
	UNBIND_ST_IPUSB_HOST,
	UNBIND_ST_FAILED
};

int modify_match_busid(char *busid, int add);


static const char ipusb_version_string[] = PACKAGE_STRING;

static const char ipusbd_help_string[] =
	"usage: ipusbd [options]			\n"
	"	-d, --debug				\n"
	"		Print debugging information.	\n"
	"						\n"
	"	-h, --help 				\n"
	"		Print this help.		\n"
	"						\n"
	"	-v, --version				\n"
	"		Show version.			\n";

	static void ipusbd_help(void)
	{
		printf("%s\n", ipusbd_help_string);
	}

static int recv_request_import(int sockfd)
{
	struct op_import_request req;
	struct op_common reply;
	struct ipusb_exported_device *edev;
	struct ipusb_usb_device pdu_udev;
	int found = 0;
	int error = 0;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	rc = ipusb_net_recv(sockfd, &req, sizeof(req));
	if (rc < 0) {
		dbg("ipusb_net_recv failed: import request");
		return -1;
	}
	PACK_OP_IMPORT_REQUEST(0, &req);

	dlist_for_each_data(host_driver->edev_list, edev,
			    struct ipusb_exported_device) {
		if (!strncmp(req.busid, edev->udev.busid, SYSFS_BUS_ID_SIZE)) {
			info("found requested device: %s", req.busid);
			found = 1;
			break;
		}
	}

	if (found) {
		/* should set TCP_NODELAY for ipusb */
		ipusb_net_set_nodelay(sockfd);

		/* export device needs a TCP/IP socket descriptor */
		rc = ipusb_host_export_device(edev, sockfd);
		if (rc < 0)
			error = 1;
	} else {
		info("requested device not found: %s", req.busid);
		error = 1;
	}

	rc = ipusb_net_send_op_common(sockfd, OP_REP_IMPORT,
				      (!error ? ST_OK : ST_NA));
	if (rc < 0) {
		dbg("ipusb_net_send_op_common failed: %#0x", OP_REP_IMPORT);
		return -1;
	}

	if (error) {
		dbg("import request busid %s: failed", req.busid);
		return -1;
	}

	memcpy(&pdu_udev, &edev->udev, sizeof(pdu_udev));
	ipusb_net_pack_usb_device(1, &pdu_udev);

	rc = ipusb_net_send(sockfd, &pdu_udev, sizeof(pdu_udev));
	if (rc < 0) {
		dbg("ipusb_net_send failed: devinfo");
		return -1;
	}

	dbg("import request busid %s: complete", req.busid);

	return 0;
}

static int send_reply_devlist(int connfd)
{
	struct ipusb_exported_device *edev;
	struct ipusb_usb_device pdu_udev;
	struct ipusb_usb_interface pdu_uinf;
	struct op_devlist_reply reply;
	int i;
	int rc;

	reply.ndev = 0;
	/* number of exported devices */
	dlist_for_each_data(host_driver->edev_list, edev,
			    struct ipusb_exported_device) {
		reply.ndev += 1;
	}
	info("exportable devices: %d", reply.ndev);

	rc = ipusb_net_send_op_common(connfd, OP_REP_DEVLIST, ST_OK);
	if (rc < 0) {
		dbg("ipusb_net_send_op_common failed: %#0x", OP_REP_DEVLIST);
		return -1;
	}
	PACK_OP_DEVLIST_REPLY(1, &reply);

	rc = ipusb_net_send(connfd, &reply, sizeof(reply));
	if (rc < 0) {
		dbg("ipusb_net_send failed: %#0x", OP_REP_DEVLIST);
		return -1;
	}

	dlist_for_each_data(host_driver->edev_list, edev,
			    struct ipusb_exported_device) {
		dump_usb_device(&edev->udev);
		memcpy(&pdu_udev, &edev->udev, sizeof(pdu_udev));

		ipusb_names_get_product(pdu_udev.vendor_name,
				sizeof(pdu_udev.vendor_name),
				edev->udev.idVendor,
				edev->udev.idProduct
				);

		ipusb_net_pack_usb_device(1, &pdu_udev);

		rc = ipusb_net_send(connfd, &pdu_udev, sizeof(pdu_udev));
		if (rc < 0) {
			dbg("ipusb_net_send failed: pdu_udev");
			return -1;
		}

		for (i = 0; i < edev->udev.bNumInterfaces; i++) {
			dump_usb_interface(&edev->uinf[i]);
			memcpy(&pdu_uinf, &edev->uinf[i], sizeof(pdu_uinf));
			ipusb_net_pack_usb_interface(1, &pdu_uinf);

			rc = ipusb_net_send(connfd, &pdu_uinf,
					    sizeof(pdu_uinf));
			if (rc < 0) {
				dbg("ipusb_net_send failed: pdu_uinf");
				return -1;
			}
		}
	}

	return 0;
}

static int recv_request_devlist(int connfd)
{
	struct op_devlist_request req;
	int rc;

	memset(&req, 0, sizeof(req));

	rc = ipusb_net_recv(connfd, &req, sizeof(req));
	if (rc < 0) {
		dbg("ipusb_net_recv failed: devlist request");
		return -1;
	}

	rc = send_reply_devlist(connfd);
	if (rc < 0) {
		dbg("send_reply_devlist failed");
		return -1;
	}

	return 0;
}

static int recv_pdu(int connfd)
{
	uint16_t code = OP_UNSPEC;
	int ret;

	ret = ipusb_net_recv_op_common(connfd, &code);
	if (ret < 0) {
		dbg("could not receive opcode: %#0x", code);
		return -1;
	}

	ret = ipusb_host_refresh_device_list();
	if (ret < 0) {
		dbg("could not refresh device list: %d", ret);
		return -1;
	}

	info("received request: %#0x(%d)", code, connfd);
	switch (code) {
	case OP_REQ_DEVLIST:
		ret = recv_request_devlist(connfd);
		break;
	case OP_REQ_IMPORT:
		ret = recv_request_import(connfd);
		break;
	case OP_REQ_DEVINFO:
	case OP_REQ_CRYPKEY:
	default:
		err("received an unknown opcode: %#0x", code);
		ret = -1;
	}

	if (ret == 0)
		info("request %#0x(%d): complete", code, connfd);
	else
		info("request %#0x(%d): failed", code, connfd);

	return ret;
}

#ifdef HAVE_LIBWRAP
static int tcpd_auth(int connfd)
{
	struct request_info request;
	int rc;

	request_init(&request, RQ_DAEMON, PROGNAME, RQ_FILE, connfd, 0);
	fromhost(&request);
	rc = hosts_access(&request);
	if (rc == 0)
		return -1;

	return 0;
}
#endif

static int do_accept(int listenfd)
{
	int connfd;
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	char host[NI_MAXHOST], port[NI_MAXSERV];
	int rc;

	memset(&ss, 0, sizeof(ss));

	connfd = accept(listenfd, (struct sockaddr *) &ss, &len);
	if (connfd < 0) {
		err("failed to accept connection");
		return -1;
	}

	rc = getnameinfo((struct sockaddr *) &ss, len, host, sizeof(host),
			 port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc)
		err("getnameinfo: %s", gai_strerror(rc));

#ifdef HAVE_LIBWRAP
	rc = tcpd_auth(connfd);
	if (rc < 0) {
		info("denied access from %s", host);
		close(connfd);
		return -1;
	}
#endif
	info("connection from %s:%s", host, port);

	return connfd;
}

static void process_request(int listenfd)
{
	int connfd;

	connfd = do_accept(listenfd);
	if (connfd < 0)
		return;

	recv_pdu(connfd);
	close(connfd);
}

static void log_addrinfo(struct addrinfo *ai)
{
	char hbuf[NI_MAXHOST];
	char sbuf[NI_MAXSERV];
	int rc;

	rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, hbuf, sizeof(hbuf),
			 sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc)
		err("getnameinfo: %s", gai_strerror(rc));

	info("listening on %s:%s", hbuf, sbuf);
}

static int listen_all_addrinfo(struct addrinfo *ai_head, int sockfdlist[])
{
	struct addrinfo *ai;
	int ret, nsockfd = 0;

	for (ai = ai_head; ai && nsockfd < MAXSOCKFD; ai = ai->ai_next) {
		sockfdlist[nsockfd] = socket(ai->ai_family, ai->ai_socktype,
					     ai->ai_protocol);
		if (sockfdlist[nsockfd] < 0)
			continue;

		ipusb_net_set_reuseaddr(sockfdlist[nsockfd]);
		ipusb_net_set_nodelay(sockfdlist[nsockfd]);

		if (sockfdlist[nsockfd] >= FD_SETSIZE) {
			close(sockfdlist[nsockfd]);
			sockfdlist[nsockfd] = -1;
			continue;
		}

		ret = bind(sockfdlist[nsockfd], ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			close(sockfdlist[nsockfd]);
			sockfdlist[nsockfd] = -1;
			continue;
		}

		ret = listen(sockfdlist[nsockfd], SOMAXCONN);
		if (ret < 0) {
			close(sockfdlist[nsockfd]);
			sockfdlist[nsockfd] = -1;
			continue;
		}

		log_addrinfo(ai);
		nsockfd++;
	}

	if (nsockfd == 0)
		return -1;

	dbg("listening on %d address%s", nsockfd, (nsockfd == 1) ? "" : "es");

	return nsockfd;
}

static struct addrinfo *do_getaddrinfo(char *host, int ai_family)
{
	struct addrinfo hints, *ai_head;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = ai_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags    = AI_PASSIVE;

	rc = getaddrinfo(host, IPUSB_PORT_STRING, &hints, &ai_head);
	if (rc) {
		err("failed to get a network address %s: %s", IPUSB_PORT_STRING,
		    gai_strerror(rc));
		return NULL;
	}

	return ai_head;
}

static void ipusbd_loop()
{
	printf("\n---------------ipusbd_loop--------------\n");
	struct addrinfo *ai_head;
	int sockfdlist[MAXSOCKFD];
	int nsockfd;
	int i;
	int rc;
	int sk_fd;
	int sk_master;
	fd_set sockets;

	if (ipusb_names_init(USBIDS_FILE))
		err("failed to open %s", USBIDS_FILE);

	if (ipusb_host_driver_open()) {
		err("please load "IPUSB_HOST_DRV_NAME".ko!");
		return;
	}

	ai_head = do_getaddrinfo(NULL, PF_UNSPEC);
	if (!ai_head)
		return;

	info("starting " PROGNAME " (%s)", ipusb_version_string);

	nsockfd = listen_all_addrinfo(ai_head, sockfdlist);
	if (nsockfd <= 0) {
		err("failed to open a listening socket");
		return;
	}
	

	sk_master = sockfdlist[nsockfd - 1] + 1;
	for (;;) {
		FD_ZERO(&sockets);
		for (i = 0; i < nsockfd; i++)
			FD_SET(sockfdlist[i], &sockets);

		rc = select(sk_master, &sockets, NULL, NULL, NULL);
		if (rc == -1) {
			err("select: %s", strerror(errno));
			break;
		}
		for (i = 0; i < nsockfd; i++) {
			sk_fd = sockfdlist[i];

			if (FD_ISSET(sk_fd, &sockets))
				process_request(sk_fd);
		}
	} 
	info("shutting down " PROGNAME);

	freeaddrinfo(ai_head);
	ipusb_host_driver_close();
	ipusb_names_free();

	return;
}

/*
*author :zhangzhiyong <zhangzhiyong@vanxum.com>
*/	
char buf[1024];
char *pstatus = "stop";
char *serverip,*serverport,*filter_flag;
int bind_flag =0;
int unbindcount = 0;

int modify_match_busid(char *busid, int add)
	{
		char bus_type[] = "usb";
		char attr_name[] = "match_busid";
		char buff[SYSFS_BUS_ID_SIZE + 4];
		char sysfs_mntpath[SYSFS_PATH_MAX];
		char match_busid_attr_path[SYSFS_PATH_MAX];
		struct sysfs_attribute *match_busid_attr;
		int rc, ret = 0;
	
		if (strlen(busid) > SYSFS_BUS_ID_SIZE - 1) {
			dbg("busid is too long");
			return -1;
		}
	
		rc = sysfs_get_mnt_path(sysfs_mntpath, SYSFS_PATH_MAX);
		if (rc < 0) {
			err("sysfs must be mounted: %s", strerror(errno));
			return -1;
		}
	
		snprintf(match_busid_attr_path, sizeof(match_busid_attr_path),
			 "%s/%s/%s/%s/%s/%s", sysfs_mntpath, SYSFS_BUS_NAME, bus_type,
			 SYSFS_DRIVERS_NAME, IPUSB_HOST_DRV_NAME, attr_name);
	
		match_busid_attr = sysfs_open_attribute(match_busid_attr_path);
		if (!match_busid_attr) {
			err("problem getting match_busid attribute: %s",
				strerror(errno));
			return -1;
		}
	
		if (add)
			snprintf(buff, SYSFS_BUS_ID_SIZE + 4, "add %s", busid);
		else
			snprintf(buff, SYSFS_BUS_ID_SIZE + 4, "del %s", busid);
	
		dbg("write \"%s\" to %s", buff, match_busid_attr->path);
	
		rc = sysfs_write_attribute(match_busid_attr, buff, sizeof(buff));
		if (rc < 0) {
			err("failed to write match_busid: %s", strerror(errno));
			ret = -1;
		}
	
		sysfs_close_attribute(match_busid_attr);
	
		return ret;
	}
	static int socket_function(char * serverip,char * serverport,char *status)
	{
		if(serverip==NULL)
		{
			printf("usbredir not rstart\n");
			return 1;
		}
		sleep(5);
		int sfd;
		struct sockaddr_in server_addr;
		int addr_len;
		int co_res;
		int port = atoi(serverport);
		sfd = socket(AF_INET, SOCK_STREAM, 0);
		if(sfd == -1){
			printf("create socket failed!!\n");
			return -1;
		}
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(port);
		server_addr.sin_addr.s_addr = inet_addr(serverip);
		addr_len = sizeof(server_addr);
		co_res = connect(sfd, (struct sockaddr*)(&server_addr), addr_len);	
		if(co_res != 0){
			printf("tcp connect failed please check your network!! restart!!\n");
			close(sfd);
			exit(1);
		}else{
			printf("tcp connect success !!\n");
			if(!strcmp(status,"stop")){
				int sendlen = strlen("stop") +1; 
				int retlen = send(sfd, "stop", sendlen, 0);
				if(retlen < 0)
				{
					printf("send stop error !!\n");
				}
				filter_flag=NULL;
				serverip=NULL;
				serverport=NULL;
			}
			close(sfd); 
		}
		return 0;
	} 
	
	static int bind_ipusb(char *busid)
	 {
		 char bus_type[] = "usb";
		 char attr_name[] = "bind";
		 char sysfs_mntpath[SYSFS_PATH_MAX];
		 char bind_attr_path[SYSFS_PATH_MAX];
		 char intf_busid[SYSFS_BUS_ID_SIZE];
		 struct sysfs_device *busid_dev;
		 struct sysfs_attribute *bind_attr;
		 struct sysfs_attribute *bConfValue;
		 struct sysfs_attribute *bNumIntfs;
		 int i, failed = 0;
		 int rc, ret = -1;
	 
		 rc = sysfs_get_mnt_path(sysfs_mntpath, SYSFS_PATH_MAX);
		 if (rc < 0) {
			 err("sysfs must be mounted: %s", strerror(errno));
			 return -1;
		 }
	 
		 snprintf(bind_attr_path, sizeof(bind_attr_path), "%s/%s/%s/%s/%s/%s",
			  sysfs_mntpath, SYSFS_BUS_NAME, bus_type, SYSFS_DRIVERS_NAME,
			  IPUSB_HOST_DRV_NAME, attr_name);
	 
		 bind_attr = sysfs_open_attribute(bind_attr_path);
		 if (!bind_attr) {
			 dbg("problem getting bind attribute: %s", strerror(errno));
			 return -1;
		 }
	 
		 busid_dev = sysfs_open_device(bus_type, busid);
		 if (!busid_dev) {
			 dbg("sysfs_open_device %s failed: %s", busid, strerror(errno));
			 goto err_close_bind_attr;
		 }
	 
		 bConfValue = sysfs_get_device_attr(busid_dev, "bConfigurationValue");
		 bNumIntfs	= sysfs_get_device_attr(busid_dev, "bNumInterfaces");
	 
		 if (!bConfValue || !bNumIntfs) {
			 dbg("problem getting device attributes: %s",
				 strerror(errno));
			 goto err_close_busid_dev;
		 }
	 
		 for (i = 0; i < atoi(bNumIntfs->value); i++) {
			 snprintf(intf_busid, SYSFS_BUS_ID_SIZE, "%s:%.1s.%d", busid,
				  bConfValue->value, i);
	 
			 rc = sysfs_write_attribute(bind_attr, intf_busid,
							SYSFS_BUS_ID_SIZE);
			 if (rc < 0) {
				 dbg("bind driver at %s failed", intf_busid);
				 failed = 1;
			 }
		 }
	 
		 if (!failed)
			 ret = 0;
	 
	 err_close_busid_dev:
		 sysfs_close_device(busid_dev);
	 err_close_bind_attr:
		 sysfs_close_attribute(bind_attr);
	 
		 return ret;
	 }
	
	 static void print_interface(char *busid, char *driver, bool parsable)
	 {
		 if (parsable)
			 printf("%s=%s#", busid, driver);
		 else
			 printf("%9s%s -> %s\n", "", busid, driver);
	 }
	  
	 static int unbind_other(char *busid)
	 {
		 char bus_type[] = "usb";
		 char intf_busid[SYSFS_BUS_ID_SIZE];
		 struct sysfs_device *busid_dev;
		 struct sysfs_device *intf_dev;
		 struct sysfs_driver *intf_drv;
		 struct sysfs_attribute *unbind_attr;
		 struct sysfs_attribute *bConfValue;
		 struct sysfs_attribute *bDevClass;
		 struct sysfs_attribute *bNumIntfs;
		 int i, rc;
		 enum unbind_status status = UNBIND_ST_OK;
	 
		 busid_dev = sysfs_open_device(bus_type, busid);
		 if (!busid_dev) {
			 dbg("sysfs_open_device %s failed: %s", busid, strerror(errno));
			 return -1;
		 }
	 
		 bConfValue = sysfs_get_device_attr(busid_dev, "bConfigurationValue");
		 bDevClass	= sysfs_get_device_attr(busid_dev, "bDeviceClass");
		 bNumIntfs	= sysfs_get_device_attr(busid_dev, "bNumInterfaces");
		 if (!bConfValue || !bDevClass || !bNumIntfs) {
			 dbg("problem getting device attributes: %s",
				 strerror(errno));
			 goto err_close_busid_dev;
		 }
	 
		 if (!strncmp(bDevClass->value, "09", bDevClass->len)) {
			 dbg("skip unbinding of hub");
			 goto err_close_busid_dev;
		 }
	 
		 for (i = 0; i < atoi(bNumIntfs->value); i++) {
			 snprintf(intf_busid, SYSFS_BUS_ID_SIZE, "%s:%.1s.%d", busid,
				  bConfValue->value, i);
			 intf_dev = sysfs_open_device(bus_type, intf_busid);
			 if (!intf_dev) {
				 dbg("could not open interface device: %s",
					 strerror(errno));
				 goto err_close_busid_dev;
			 }
	 
			 dbg("%s -> %s", intf_dev->name,  intf_dev->driver_name);
	 
			 if (!strncmp("unknown", intf_dev->driver_name, SYSFS_NAME_LEN))
				 /* unbound interface */
				 continue;
	 
			 if (!strncmp(IPUSB_HOST_DRV_NAME, intf_dev->driver_name,
					  SYSFS_NAME_LEN)) {
				 /* already bound to ipusb-host */
				 status = UNBIND_ST_IPUSB_HOST;
				 continue;
			 }
	 
			 /* unbinding */
			 intf_drv = sysfs_open_driver(bus_type, intf_dev->driver_name);
			 if (!intf_drv) {
				 dbg("could not open interface driver on %s: %s",
					 intf_dev->name, strerror(errno));
				 goto err_close_intf_dev;
			 }
	 
			 unbind_attr = sysfs_get_driver_attr(intf_drv, "unbind");
			 if (!unbind_attr) {
				 dbg("problem getting interface driver attribute: %s",
					 strerror(errno));
				 goto err_close_intf_drv;
			 }
	 
			 rc = sysfs_write_attribute(unbind_attr, intf_dev->bus_id,
							SYSFS_BUS_ID_SIZE);
			 if (rc < 0) {
				 /* NOTE: why keep unbinding other interfaces? */
				 dbg("unbind driver at %s failed", intf_dev->bus_id);
				 status = UNBIND_ST_FAILED;
			 }
	 
			 sysfs_close_driver(intf_drv);
			 sysfs_close_device(intf_dev);
		 }
	 
		 goto out;
	 
	 err_close_intf_drv:
		 sysfs_close_driver(intf_drv);
	 err_close_intf_dev:
		 sysfs_close_device(intf_dev);
	 err_close_busid_dev:
		 status = UNBIND_ST_FAILED;
	 out:
		 sysfs_close_device(busid_dev);
	 
		 return status;
	 }
	
	 static int bind_device(char *busid)
	{
		int rc;
	
		rc = unbind_other(busid);
		if (rc == UNBIND_ST_FAILED) {
			err("could not unbind driver from device on busid %s", busid);
			return -1;
		} else if (rc == UNBIND_ST_IPUSB_HOST) {
			err("device on busid %s is already bound to %s", busid,
				IPUSB_HOST_DRV_NAME);
			return -1;
		}
	
		rc = modify_match_busid(busid, 1);
		if (rc < 0) {
			err("unable to bind device on %s", busid);
			return -1;
		}
	
		rc = bind_ipusb(busid);
		if (rc < 0) {
			err("could not bind device to %s", IPUSB_HOST_DRV_NAME);
			modify_match_busid(busid, 0);
			return -1;
		}
	
		printf("bind device on busid %s: complete\n", busid);
	
		return 0;
	}
	 static int unbind_device(char *busid)
	{
		char bus_type[] = "usb";
		struct sysfs_driver *ipusb_host_drv;
		struct sysfs_device *dev;
		struct dlist *devlist;
		int verified = 0;
		int rc, ret = -1;
	
		char attr_name[] = "bConfigurationValue";
		char sysfs_mntpath[SYSFS_PATH_MAX];
		char busid_attr_path[SYSFS_PATH_MAX];
		struct sysfs_attribute *busid_attr;
		char *val = NULL;
		int len;
	
		/* verify the busid device is using ipusb-host */
		ipusb_host_drv = sysfs_open_driver(bus_type, IPUSB_HOST_DRV_NAME);
		if (!ipusb_host_drv) {
			err("could not open %s driver: %s", IPUSB_HOST_DRV_NAME,
				strerror(errno));
			return -1;
		}
	
		devlist = sysfs_get_driver_devices(ipusb_host_drv);
		if (!devlist) {
			err("%s is not in use by any devices", IPUSB_HOST_DRV_NAME);
			goto err_close_ipusb_host_drv;
		}
	
		dlist_for_each_data(devlist, dev, struct sysfs_device) {
			if (!strncmp(busid, dev->name, strlen(busid)) &&
				!strncmp(dev->driver_name, IPUSB_HOST_DRV_NAME,
					 strlen(IPUSB_HOST_DRV_NAME))) {
				verified = 1;
				break;
			}
		}
	
		if (!verified) {
			err("device on busid %s is not using %s", busid,
				IPUSB_HOST_DRV_NAME);
			goto err_close_ipusb_host_drv;
		}
	
		rc = sysfs_get_mnt_path(sysfs_mntpath, SYSFS_PATH_MAX);
		if (rc < 0) {
			err("sysfs must be mounted: %s", strerror(errno));
			return -1;
		}
	
		snprintf(busid_attr_path, sizeof(busid_attr_path), "%s/%s/%s/%s/%s/%s",
			 sysfs_mntpath, SYSFS_BUS_NAME, bus_type, SYSFS_DEVICES_NAME,
			 busid, attr_name);
	
		/* read a device attribute */
		busid_attr = sysfs_open_attribute(busid_attr_path);
		if (!busid_attr) {
			err("could not open %s/%s: %s", busid, attr_name,
				strerror(errno));
			return -1;
		}
	
		if (sysfs_read_attribute(busid_attr) < 0) {
			err("problem reading attribute: %s", strerror(errno));
			goto err_out;
		}
	
		len = busid_attr->len;
		val = malloc(len);
		*val = *busid_attr->value;
		sysfs_close_attribute(busid_attr);
	
		/* notify driver of unbind */
		rc = modify_match_busid(busid, 0);
		if (rc < 0) {
			err("unable to unbind device on %s", busid);
			goto err_out;
		}
	
		/* write the device attribute */
		busid_attr = sysfs_open_attribute(busid_attr_path);
		if (!busid_attr) {
			err("could not open %s/%s: %s", busid, attr_name,
				strerror(errno));
			return -1;
		}
	
		rc = sysfs_write_attribute(busid_attr, val, len);
		if (rc < 0) {
			err("problem writing attribute: %s", strerror(errno));
			goto err_out;
		}
		sysfs_close_attribute(busid_attr);
	
		ret = 0;
		printf("unbind device on busid %s: complete\n", busid);
	
	err_out:
		free(val);
	err_close_ipusb_host_drv:
		sysfs_close_driver(ipusb_host_drv);
	
		return ret;
	}
	
	 static void print_device(char *busid, char *vendor, char *product,bool parsable)
	{
		if (parsable)
			printf("busid=%s#usbid=%.4s:%.4s#", busid, vendor, product);
		else
			printf(" - busid %s (%.4s:%.4s)\n", busid, vendor, product);
	}
	
	static int devcmp(void *a, void *b)
	{
		return strcmp(a, b);
	}
	
	
	static int is_device(void *x)
	{
		struct sysfs_attribute *devpath;
		struct sysfs_device *dev = x;
		int ret = 0;			 
		devpath = sysfs_get_device_attr(dev, "devpath");
		if (devpath && *devpath->value != '0')
			ret = 1;			 
		return ret;
	}
	
	 static int list_devices(bool parsable,int bind_flag)
	 {
		 char bus_type[] = "usb";
		 char busid[SYSFS_BUS_ID_SIZE];
		 struct sysfs_bus *ubus;
		 struct sysfs_device *dev;
		 struct sysfs_device *intf;
		 struct sysfs_attribute *idVendor;
		 struct sysfs_attribute *idProduct;
		 struct sysfs_attribute *bConfValue;
		 struct sysfs_attribute *bNumIntfs;
		 struct dlist *devlist;
		 int i;
		 int ret = -1;
	 
		 ubus = sysfs_open_bus(bus_type);
		 if (!ubus) {
			 err("could not open %s bus: %s", bus_type, strerror(errno));
			 return -1;
		 }
	 
		 devlist = sysfs_get_bus_devices(ubus);
		 if (!devlist) {
			 err("could not get %s bus devices: %s", bus_type,
				 strerror(errno));
			 goto err_out;
		 }
	 
		 /* remove interfaces and root hubs from device list */
		 dlist_filter_sort(devlist, is_device, devcmp);
	 
		 if (!parsable) {
			 printf("Local USB devices\n");
			 printf("=================\n");
		 }
		 dlist_for_each_data(devlist, dev, struct sysfs_device) {
			 idVendor	= sysfs_get_device_attr(dev, "idVendor");
			 idProduct	= sysfs_get_device_attr(dev, "idProduct");
			 bConfValue = sysfs_get_device_attr(dev, "bConfigurationValue");
			 bNumIntfs	= sysfs_get_device_attr(dev, "bNumInterfaces");
			
			 if (!idVendor || !idProduct || !bConfValue || !bNumIntfs) {
				 err("problem getting device attributes: %s",
					 strerror(errno));
				 goto nonlabel;
			 }
	 		
			 print_device(dev->bus_id, idVendor->value, idProduct->value,parsable);
			 for (i = 0; i < atoi(bNumIntfs->value); i++) {
				 snprintf(busid, sizeof(busid), "%s:%.1s.%d",
					  dev->bus_id, bConfValue->value, i);
				 intf = sysfs_open_device(bus_type, busid);
				 if (!intf) {
					 err("could not open device interface: %s",
						 strerror(errno));
					 goto nonlabel;
				 }
				 print_interface(busid, intf->driver_name, parsable);
				 sysfs_close_device(intf);

				 if(!strcmp("hub",intf->driver_name))
				 {
				 	goto nonlabel; 
				 }
				
				 if(!strcmp("usbhid",intf->driver_name))
				{
						goto nonlabel; 
				}
				 
				  if((!strcmp("vanxum-usbredir",intf->driver_name))&& (bind_flag == 1) )
				 {
				 	goto nonlabel; 
				 }

				  if((strcmp("vanxum-usbredir",intf->driver_name)) && (bind_flag ==0))
				  {
				  		goto nonlabel; 
				  }
			 }
			 
			if(bind_flag){
				 bind_device(dev->bus_id);
				 sleep(2);
			 }else if(bind_flag== 0){
				 unbind_device(dev->bus_id);
			 }
			 
			 nonlabel:
			 printf("\n");
		 }
	 
		 ret = 0;
	 
	err_out:
		sysfs_close_bus(ubus);
	return ret;
}
	
	static void *thread_export(void *arg)
	 {
		char * b=(char *)arg;
		printf("b=%s\n",b);
		printf("Enter the thread_export!!\n"); 	 
		int configfd;
		int reflag;
		int len;
		int fd;
		reflag=access("/tmp/usbredir_config.txt",0);
		if(reflag==0){
			if((configfd = open("/tmp/usbredir_config.txt", O_RDONLY)) < 0){
				printf("Open /tmp/usbredir_config.txt Failed\n");
			}
			len = read(configfd,buf,1024);
			if(len>0){
				pstatus=strtok(buf," ");
				serverip=strtok(NULL," ");
				filter_flag=strtok(NULL," ");
				serverport=strtok(NULL," ");
				if(!strcmp("start",pstatus)){
					socket_function(serverip,serverport,pstatus);					 
				}
			}
		}
		int flag;
		flag=access("/tmp/usbredir",0);
		if(flag !=0){
			if(mkfifo("/tmp/usbredir", 0666) < 0 && errno!=EEXIST){
				printf("Create usbredir FIFO Failed\n");
				return NULL;
			}
		}
		 
		if((fd = open("/tmp/usbredir", O_RDONLY)) < 0){
			printf("Open FIFO Failed\n");
			return NULL;
		}
		while(true){
			len = read(fd, buf, 1024);
			if(len > 0){
				if(!strcmp("stop",buf)){
					printf("Recive stop usb-redir command!\n");
					pstatus = "stop";
					printf("Stop usb-redir success!!\n");	
					socket_function(serverip,serverport,"stop");
				}else{
					printf("Recive start usb-redir command!\n");
					pstatus=strtok(buf," ");
					serverip=strtok(NULL," ");
					filter_flag=strtok(NULL," ");
					serverport=strtok(NULL," ");
					if(!strcmp("start",pstatus)){
						socket_function(serverip,serverport,pstatus);
					}
				}
			}
			usleep(50000);
		}
		return NULL;
	}
	
	static void *thread_bind_unbind(void *arg)
	{
		char * a=(char *)arg;
		printf("a=%s\n",a);
		printf("Enter the thread_bind_unbind!!\n");
		bool parsable = false;
		while(true){
			if(!strcmp(pstatus,"start"))
			{
				bind_flag=1;
				unbindcount = 0;
				list_devices(parsable,bind_flag);
				
			}else{
				if(unbindcount == 0){
					bind_flag = 0;
					list_devices(parsable,bind_flag);
					unbindcount=1;
				}
			}
			sleep(3);
		}
		return NULL;
	}
	 
	 
	int main(int argc, char *argv[])
	{
		pthread_t export_threadid; 
		int s = pthread_create(&export_threadid, NULL, thread_export, NULL);
		if (s!= 0)
		{
			printf ("create thread_export error!!\n");
			return -1;
		}
		
		pthread_t bind_unbind_threadid; 
		int s1 = pthread_create(&bind_unbind_threadid, NULL, thread_bind_unbind, NULL);
		if (s1!= 0)
		{
			printf ("create thread_bind_unbind error!!\n");
			return -1;
		}
		printf("Enter the listen process!!\n"); 
		static const struct option longopts[] = {
		{ "debug",   no_argument, NULL, 'd' },
		{ "help",    no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL,	     0,           NULL,  0  }
		};
		int opt;
		ipusb_use_stderr = 1;
		ipusb_use_syslog = 0;
		for (;;) {
			opt = getopt_long(argc, argv, "Ddhv", longopts, NULL);

			if (opt == -1)
				break;

			switch (opt) {
			case 'd':
				ipusb_use_debug = 1;
				break;
			case 'h':
				ipusbd_help();
				return EXIT_SUCCESS;
			case 'v':
				printf(PROGNAME " (%s)\n", ipusb_version_string);
				return EXIT_SUCCESS;
			default:
				ipusbd_help();
				return EXIT_FAILURE;
			}
		}
		ipusbd_loop();
		return EXIT_SUCCESS;
	}

