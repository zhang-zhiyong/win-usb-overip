#include "ipusb.h"
#include <cstdio>
#include "ipusbq_task.h"
#include<Windows.h>
#include<stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h> 
#include <ctype.h>

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


/*
*Author: zhangzhiyong
*Date:2019/2/19
*Vusb_Server main function start
*/


DWORD WINAPI ThreadExportDevice(LPVOID);
struct host_devs* export_device;
struct dev_info * export_device_info;
char  hostaddr[32];
struct usbchannelstu{
	char *usbchannelbusid; 
	int process_id;
}usbchannel[8];

int serarch(int intpid)
{
	int ret=-1;
	char strpid[32];
	itoa(intpid,strpid,10);
	char strsearchcmd[256] = "tasklist /FI \"PID eq ";
	strcat(strsearchcmd,strpid);
	strcat(strsearchcmd,"\"  /FI \"IMAGENAME eq ipusb_start.exe\" | findstr ipusb_start.exe");
	ret=system(strsearchcmd);
	if(ret == 0)
	{ 
		return 1;
	}else{
		return 0;
	}
}

void stop(int intpid)
{
    char strpid[32];
	itoa(intpid,strpid,10);
    char strsearchcmd[256] = "taskkill /pid ";
    strcat(strsearchcmd,strpid);
    strcat(strsearchcmd," /f");
    system(strsearchcmd);
}


/*
*Function:This function include an endless loop,for querying exportdevice every 3 seconds
*/
DWORD WINAPI ThreadExportDevice(LPVOID p)
{   
	printf("Begin to start ThreadExportDevice!!\n");
	
	for(int i=0;i<8;i++){
		usbchannel[i].usbchannelbusid=NULL;
		usbchannel[i].process_id=-1;
	}
	
	while(true){
		printf("ThreadExportDevice main loop every 3 seconds\n");
		if(strcmp("stop",hostaddr)){
			
			for(int j=0;j<8;j++)
			{
				if(usbchannel[j].usbchannelbusid != NULL)
				{
					if(!serarch(usbchannel[j].process_id))
					{
						usbchannel[j].usbchannelbusid = NULL;
						usbchannel[j].process_id = -1;
						continue;
					}
					printf("++++++++++++++++++++++++\n");
				}
			}
			
			printf("ThreadExportDevice form hostaddr=%s\n",hostaddr);
			export_device=show_exported_devices(hostaddr);
			if(export_device->fail == 1)
			{
				printf("net work unconnet to client!!\n");
				printf("begin stop Server\n");
				sprintf(hostaddr,"%s","stop");
				goto tobegin;
			}
			export_device_info=export_device->dev;
			printf("export_device->n_devs=%d\n",export_device->n_devs);
			if(export_device->n_devs >0){				
				for(int i =0;i < export_device->n_devs;i++)
				{	
					int  countflag=0;
					for(int j=0;j<8;j++){
						if(usbchannel[j].usbchannelbusid !=NULL){
							if(strcmp(usbchannel[j].usbchannelbusid,export_device_info->busid)){
								continue;
							}else{
								countflag++;
								if(serarch(usbchannel[j].process_id)){
									printf("This device is already running!!\n");
									if(countflag > 1)
									{
										usbchannel[j].process_id = -1;
										usbchannel[j].usbchannelbusid=NULL;
									}
								}else{
									printf("This is a new device need to redirect because process id is not running!!\n");
									STARTUPINFO si = { 0 };
									si.cb = sizeof(si);
									PROCESS_INFORMATION pi;
									char szCmdline[MAX_PATH];
									sprintf(szCmdline,"%s %s %s","ipusb_start.exe",hostaddr,export_device_info->busid);	
									char *CStr = szCmdline;
									size_t len = strlen(CStr) + 1;
									size_t converted = 0;
									wchar_t *WStr;
									WStr=(wchar_t*)malloc(len*sizeof(wchar_t));
									mbstowcs_s(&converted, WStr, len, CStr, _TRUNCATE);
									if(CreateProcess(NULL,WStr,NULL,NULL,TRUE,0,NULL,NULL,&si,&pi))
									{
										//printf("Create Process Success\n!!\n");
										usbchannel[j].process_id=pi.dwProcessId;
									}else{
										//printf("Create Process Failed!!\n");
									}
								}
							}
						}
					
					}
					
					if(!countflag)
					{
						printf("This device is a new device need to be redirect!!\n");
						STARTUPINFO si = { 0 };//该结构用于指定新进程的主窗口特性
						si.cb = sizeof(si);
						PROCESS_INFORMATION pi;//指定新进程的主窗口特性
						char szCmdline[MAX_PATH];
						sprintf(szCmdline,"%s %s %s","ipusb_start.exe",hostaddr,export_device_info->busid);
						//printf("szCmdline = %s\n",szCmdline);		
						char *CStr = szCmdline;
						size_t len = strlen(CStr) + 1;
						size_t converted = 0;
						wchar_t *WStr;
						WStr=(wchar_t*)malloc(len*sizeof(wchar_t));
						mbstowcs_s(&converted, WStr, len, CStr, _TRUNCATE);
						if(CreateProcess(NULL,WStr,NULL,NULL,TRUE,0,NULL,NULL,&si,&pi))
						{
							printf("Create Process Success\n!!\n");
						}else{
							printf("Create Process Failed!!\n");
						}
						for(int j=0;j<8;j++){
							if(usbchannel[j].usbchannelbusid==NULL)
							{
								usbchannel[j].usbchannelbusid=export_device_info->busid;
								usbchannel[j].process_id=pi.dwProcessId;
								break;
							}
						}
						countflag =0;
					}
					Sleep(1000);
					export_device_info++;
				}			
			}	
		}else{
			for(int i=0;i<8;i++)
			{
				if(usbchannel[i].process_id == -1){
					continue;
				}else{
					if(serarch(usbchannel[i].process_id)){
						stop(usbchannel[i].process_id);
					}
					usbchannel[i].usbchannelbusid=NULL;
					usbchannel[i].process_id = -1;
				}
			}
		}	
	tobegin:
		Sleep(3000);
	}
    return 0;
}


int main(int argc, char *argv[])
{
	printf("Start vanxum vUsb_Server Version=1.0.0\n");
	sprintf(hostaddr,"%s","stop");
	if(init_winsock()){
		printf("can't init winsock");
		return 0;
	}
	HANDLE hThread;
    DWORD  threadId;
	hThread = CreateThread(NULL, 0, ThreadExportDevice, 0, 0, &threadId); // 创建线程
	
	//创建套接字
	SOCKET slisten = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
     if(slisten == INVALID_SOCKET)
     {
         printf("socket error !\n");
         return 0;
     }
	//绑定IP和端口
     sockaddr_in sin;
     sin.sin_family = AF_INET;
     sin.sin_port = htons(3241);
     sin.sin_addr.S_un.S_addr = INADDR_ANY; 
     if(bind(slisten, (LPSOCKADDR)&sin, sizeof(sin)) == SOCKET_ERROR)
     {
         printf("bind error !\n");
		 return 0;
     }
	 //开始监听
     if(listen(slisten, 5) == SOCKET_ERROR)
     {
         printf("listen error !\n");
         return 0;
     }

	 //循环接收数据
     SOCKET sClient;
     sockaddr_in remoteAddr;
     int nAddrlen = sizeof(remoteAddr);
     char revData[255]; 

	while(true){
		printf("等待连接...\n");
        sClient = accept(slisten, (SOCKADDR *)&remoteAddr, &nAddrlen);
        if(sClient == INVALID_SOCKET)
        {
            printf("accept error !\n");
            continue;
        }
		printf("接受到一个连接：%s \r\n", inet_ntoa(remoteAddr.sin_addr));
		if(!strcmp("stop",hostaddr)){
			 sprintf(hostaddr,"%s",inet_ntoa(remoteAddr.sin_addr));
			 printf("Accept a client remote addrss=%s",hostaddr);
			 closesocket(sClient);
			 continue;

		 }else if(!strcmp(hostaddr,inet_ntoa(remoteAddr.sin_addr))){
			 int ret = recv(sClient, revData, 255, 0);
			 if(ret > 0){
				revData[ret] = 0x00;
				printf("Recive Data is revData=%s ",revData);
				if(strcmp(revData,"stop")==0){
					closesocket(sClient);
					sprintf(hostaddr,"%s","stop");
					continue;
				 }
			 }
		 
		 }else{
			closesocket(sClient);
			continue;
		 }
	 }
	closesocket(slisten);
    WSACleanup();
	return 0;
}



