#include "ipusb.h"
#include <cstdio>
#include "ipusbq_task.h"
#include <string.h>
#include <windows.h>
#include<stdio.h>


int query_interface0(SOCKET sockfd, char * busid, struct usb_interface * uinf0)
{
	int ret;
	struct op_devlist_reply rep;
	uint16_t code = OP_REP_DEVLIST;
	uint32_t i,j;
	char product_name[100];
	char class_name[100];
	struct usb_device udev;
	struct usb_interface uinf;
	int found=0;

	memset(&rep, 0, sizeof(rep));

	ret = ipusb_send_op_common(sockfd, OP_REQ_DEVLIST, 0);
	if (ret < 0) {
		printf("send op_common");
		return -1;
	}

	ret = ipusb_recv_op_common(sockfd, &code);
	if (ret < 0) {
		printf("recv op_common");
		return -1;
	}

	ret = ipusb_recv(sockfd, (void *) &rep, sizeof(rep));
	if (ret < 0) {
		printf("recv op_devlist");
		return -1;
	}

	PACK_OP_DEVLIST_REPLY(0, &rep);
	dbg("exportable %d devices", rep.ndev);

	for (i=0; i < rep.ndev; i++) {

		memset(&udev, 0, sizeof(udev));

		ret = ipusb_recv(sockfd, (void *) &udev, sizeof(udev));
		if (ret < 0) {
			printf("recv usb_device[%d]", i);
			return -1;
		}
		pack_usb_device(0, &udev);
		ipusb_names_get_product(product_name, sizeof(product_name),
				udev.idVendor, udev.idProduct);
		ipusb_names_get_class(class_name, sizeof(class_name), udev.bDeviceClass,
				udev.bDeviceSubClass, udev.bDeviceProtocol);

		dbg("%8s: %s", udev.busid, product_name);
		dbg("%8s: %s", " ", udev.path);
		dbg("%8s: %s", " ", class_name);

		for (j=0; j < udev.bNumInterfaces; j++) {

			ret = ipusb_recv(sockfd, (void *) &uinf, sizeof(uinf));
			if (ret < 0) {
				printf("recv usb_interface[%d]", j);
				return -1;
			}

			pack_usb_interface(0, &uinf);
			if(!strcmp(udev.busid, busid)&&j==0){
				memcpy(uinf0, &uinf, sizeof(uinf));
				found=1;
			}
			ipusb_names_get_class(class_name, sizeof(class_name),
					uinf.bInterfaceClass,
					uinf.bInterfaceSubClass,
					uinf.bInterfaceProtocol);

			dbg("%8s: %2d - %s", " ", j, class_name);
		}
	}
	if(found)
		return 0;
	return -1;
}

static int import_device(struct usb_device *udev,
		struct usb_interface *uinf0,
		HANDLE *devfd)
{
	HANDLE fd;
	int port, ret;

	fd = ipusb_vbus_open();
	if (INVALID_HANDLE_VALUE == fd) {
		printf("open vbus driver");
		return -1;
	}

	port = ipusb_vbus_get_free_port(fd);
	if (port <= 0) {
		printf("no free port");
		CloseHandle(fd);
		return -1;
	}

	ret = ipusb_vbus_attach_device(fd, port, udev, uinf0);

	if (ret < 0) {
		printf("import device");
		CloseHandle(fd);
		return -1;
	}
	dbg("devfd:%p\n",devfd);
	*devfd=fd;

	return port;
}

static int query_import_device(int sockfd, char *busid,
		struct usb_interface *uinf0, HANDLE * fd)
{
	int ret;
	struct op_import_request request;
	struct op_import_reply   reply;
	uint16_t code = OP_REP_IMPORT;

	memset(&request, 0, sizeof(request));
	memset(&reply, 0, sizeof(reply));

	/* send a request */
	ret = ipusb_send_op_common(sockfd, OP_REQ_IMPORT, 0);
	if (ret < 0) {
		printf("send op_common");
		return -1;
	}

	strncpy(request.busid, busid, sizeof(request.busid));
	request.busid[sizeof(request.busid)-1]=0;

	PACK_OP_IMPORT_REQUEST(0, &request);

	ret = ipusb_send(sockfd, (void *) &request, sizeof(request));
	if (ret < 0) {
		printf("send op_import_request");
		return -1;
	}

	/* recieve a reply */
	ret = ipusb_recv_op_common(sockfd, &code);
	if (ret < 0) {
		printf("recv op_common");
		return -1;
	}

	ret = ipusb_recv(sockfd, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		printf("recv op_import_reply");
		return -1;
	}

	PACK_OP_IMPORT_REPLY(0, &reply);

	/* check the reply */
	if (strncmp(reply.udev.busid, busid, sizeof(reply.udev.busid))) {
		printf("recv different busid %s", reply.udev.busid);
		return -1;
	}

	/* import a device */
        return import_device(&reply.udev, uinf0, fd);
}

/*
 * attach_device - blocking until connection aborts
 */
int attach_device(char * host, char * busid, volatile bool *stop_cond)
{

	printf("host=%s busid=%s\n",host,busid);

	SOCKET sockfd;
	int rhport;
	HANDLE devfd=INVALID_HANDLE_VALUE;
	struct usb_interface uinf;

        sockfd = tcp_connect(host, IPUSB_PORT_STRING);
        if (INVALID_SOCKET == sockfd)
                return 1;

        if(query_interface0(sockfd, busid, &uinf))
                return 1;

	    closesocket(sockfd);
        sockfd = tcp_connect(host, IPUSB_PORT_STRING);
        if (INVALID_SOCKET == sockfd)
                return 1;

        rhport = query_import_device(sockfd, busid, &uinf, &devfd);
        if (rhport < 0) {
                closesocket(sockfd);
                return 1;
        }

	info("new usb device attached to usbvbus port %d\n", rhport);
        ipusb_vbus_forward(sockfd, devfd, stop_cond);
	
	CloseHandle(devfd);
        ipusb_vbus_detach_device(devfd,rhport);
	closesocket(sockfd);

        return 0;
}

int detach_port(char *port)
{
	signed char addr=atoi(port);
	HANDLE fd;
	int ret;

	fd = ipusb_vbus_open();
	if (INVALID_HANDLE_VALUE == fd) {
		printf("open vbus driver");
		return -1;
	}
	ret = ipusb_vbus_detach_device(fd, addr);
	CloseHandle(fd);
	return ret;
}

int show_port_status(void)
{
	HANDLE fd;
	int i;
	char buf[128];

	fd = ipusb_vbus_open();
	if (INVALID_HANDLE_VALUE == fd) {
		printf("open vbus driver");
		return -1;
	}
	if(ipusb_vbus_get_ports_status(fd, buf, sizeof(buf))){
		printf("get port status");
		return -1;
	}
	info("max used port:%d\n", buf[0]);
	for(i=1; i<=buf[0]; i++){
		if(buf[i])
			info("port %d: used\n", i);
		else
			info("port %d: idle\n", i);
	}
	CloseHandle(fd);
	return 0;
}


static int query_exported_devices(SOCKET sockfd, struct host_devs *devs)
{
        int ret;
        struct op_devlist_reply rep;
        uint16_t code = OP_REP_DEVLIST;
        uint32_t i,j;
        struct usb_device udev;

        memset(&rep, 0, sizeof(rep));

        ret = ipusb_send_op_common(sockfd, OP_REQ_DEVLIST, 0);
        if (ret < 0) {
                printf("send op_common");
                goto err_out;
        }

        ret = ipusb_recv_op_common(sockfd, &code);
        if (ret < 0) {
                printf("recv op_common");
                goto err_out;
        }

        ret = ipusb_recv(sockfd, (void *) &rep, sizeof(rep));
        if (ret < 0) {
                printf("recv op_devlist");
                goto err_out;
        }

        PACK_OP_DEVLIST_REPLY(0, &rep);
        if (rep.ndev >= MAX_DEVS_PER_HOST)
                rep.ndev = MAX_DEVS_PER_HOST;
        devs->n_devs = rep.ndev;

        for (i=0; i < rep.ndev; i++) {

                memset(&udev, 0, sizeof(udev));

                ret = ipusb_recv(sockfd, (void *) &udev, sizeof(udev));
                if (ret < 0) {
                        printf("recv usb_device[%d]", i);
                        goto err_out;
                }
                pack_usb_device(0, &udev);

                strcpy(devs->dev[i].name, udev.vendor_name);
                strcpy(devs->dev[i].path, udev.path);
                strcpy(devs->dev[i].busid, udev.busid);

                for (j=0; j < udev.bNumInterfaces; j++) {
                        struct usb_interface uinf;

                        ret = ipusb_recv(sockfd, (void *) &uinf, sizeof(uinf));
                        if (ret < 0) {
                                printf("recv usb_interface[%d]", j);
                                goto err_out;
                        }
                        pack_usb_interface(0, &uinf);
                }
        }
        return rep.ndev;

err_out:
        devs->fail = -1;
        return -1;
}

struct host_devs * show_exported_devices(char *host)
{
        SOCKET sockfd;
        struct host_devs *devs;

        devs = new struct host_devs;
        devs->fail = 0;

        sockfd = tcp_connect(host, IPUSB_PORT_STRING);
        if (INVALID_SOCKET == sockfd){
                devs->fail = 1;
                return devs;
        }

        query_exported_devices(sockfd, devs);
        closesocket(sockfd);
        return devs;
}


char * hostaddr;
char * busid;

int main(int argc, char *argv[])
{
	printf("Begin to start vUSB import %s \n",argv[1]);
	
	if(init_winsock()){
		printf("can't init winsock");
		return 0;
	}
	hostaddr=argv[1];
	busid = argv[2];
	attach_device(hostaddr,busid,NULL);
	return 0;
}

