
#ifdef __GNUC__
#define INITGUID
#endif
#include "ipusb.h"
#include "public.h"
#include "win_stub.h"
#define BIG_SIZE 1000000
//char err_buf[256];

static WCHAR * ipusb_vbus_dev_node_name(WCHAR *buf, unsigned long buf_len)
{
	HDEVINFO dev_info;
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
	PSP_DEVICE_INTERFACE_DETAIL_DATA dev_interface_detail = NULL;
	unsigned long len;
        WCHAR *ret = NULL;

	dev_info = SetupDiGetClassDevs(
		(LPGUID) &GUID_DEVINTERFACE_BUSENUM_IPUSB, /* ClassGuid */
		NULL,	/* Enumerator */
		NULL,	/* hwndParent */
		DIGCF_PRESENT|DIGCF_DEVICEINTERFACE /* Flags */
	);

	if (INVALID_HANDLE_VALUE == dev_info) {
		printf("SetupDiGetClassDevs failed: %ld\n", GetLastError());
		return NULL;
	}

	dev_interface_data.cbSize = sizeof (dev_interface_data);

	if (!SetupDiEnumDeviceInterfaces(
		dev_info, /* DeviceInfoSet */
		NULL, /* DeviceInfoData */
		(LPGUID)
		&GUID_DEVINTERFACE_BUSENUM_IPUSB, /* InterfaceClassGuid */
		0, /* MemberIndex */
		&dev_interface_data /* DeviceInterfaceData */
	)) {
		if (ERROR_NO_MORE_ITEMS == GetLastError())
			printf("usbvbus interface is not registered\n");
		else
			printf("unknown error when get interface_data\n");
		goto end;
	}
	SetupDiGetDeviceInterfaceDetail(
		dev_info, /* DeviceInfoSet */
		&dev_interface_data, /* DeviceInterfaceData */
		NULL,	/* DeviceInterfaceDetailData */
		0,	/* DeviceInterfaceDetailDataSize */
		&len,	/* RequiredSize */
		NULL	/* DeviceInfoData */);

	if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
		printf("Error in SetupDiGetDeviceInterfaceDetail%ld\n",
		       GetLastError());
		goto end;
	}

        dev_interface_detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(len);
	if(NULL == dev_interface_detail){
		printf("can't malloc %lu size memoery", len);
		goto end;
	}
	dev_interface_detail->cbSize = sizeof (*dev_interface_detail);

	if (!SetupDiGetDeviceInterfaceDetail(
		dev_info, /* DeviceInfoSet */
		&dev_interface_data, /* DeviceInterfaceData */
		dev_interface_detail,	/* DeviceInterfaceDetailData */
		len,	/* DeviceInterfaceDetailDataSize */
		&len,	/* RequiredSize */
		NULL	/* DeviceInfoData */)){
		printf("Error in SetupDiGetDeviceInterfaceDetail\n");
		goto end;
        }
        wcscpy(buf, dev_interface_detail->DevicePath);
	ret = buf;
end:
	if(dev_interface_detail)
		free(dev_interface_detail);
	SetupDiDestroyDeviceInfoList(dev_info);
	return ret;
}

HANDLE ipusb_vbus_open(void)
{
        WCHAR buf[256];

        if(ipusb_vbus_dev_node_name(buf, sizeof(buf)) == NULL)
                return INVALID_HANDLE_VALUE;

        return	CreateFile(buf,
			GENERIC_READ|GENERIC_WRITE,
			  0,
			  NULL,
			  OPEN_EXISTING,
			  FILE_FLAG_OVERLAPPED,
                          NULL);
}

int ipusb_vbus_get_ports_status(HANDLE fd, char *buf, int l)
{
	int ret;
	unsigned long len;
	ioctl_usbvbus_get_ports_status *st;
	
	st =(ioctl_usbvbus_get_ports_status *)buf;
	if(l!=sizeof(*st))
		return -1;

	ret = DeviceIoControl(fd, IOCTL_USBVBUS_GET_PORTS_STATUS,
				NULL, 0, st, sizeof(*st), &len, NULL);
	if(ret&&len==sizeof(*st))
		return 0;
	else
		return -1;
}

int ipusb_vbus_get_free_port(HANDLE fd)
{
        unsigned int i;
	char buf[128];
	if(ipusb_vbus_get_ports_status(fd, buf, sizeof(buf)))
		return -1;
	for(i=1;i<sizeof(buf);i++){
		if(!buf[i])
			return i;
	}
	return -1;
}

int ipusb_vbus_detach_device(HANDLE fd, int port)
{
	int ret;
	ioctl_usbvbus_unplug  unplug;
	unsigned long unused;

	unplug.addr = port;
	ret = DeviceIoControl(fd, 
				IOCTL_USBVBUS_UNPLUG_HARDWARE,
				&unplug, 
				sizeof(unplug), 
				NULL, 
				0, 
				&unused, 
				NULL);
	if(ret)
		return 0;
	return -1;
}

int ipusb_vbus_attach_device(HANDLE fd, int port, struct usb_device *udev,
		struct usb_interface *uinf0)
{
	int ret;
	ioctl_usbvbus_plugin  plugin;
	unsigned long unused;

	plugin.devid  = ((udev->busnum << 16)|udev->devnum);
	plugin.vendor = udev->idVendor;
	plugin.product = udev->idProduct;
	plugin.version = udev->bcdDevice;
	plugin.speed = udev->speed;
	plugin.inum = udev->bNumInterfaces;
	plugin.int0_class = uinf0->bInterfaceClass;
	plugin.int0_subclass = uinf0->bInterfaceSubClass;
	plugin.int0_protocol = uinf0->bInterfaceProtocol;
	plugin.addr = port;

	ret = DeviceIoControl(fd, 
				IOCTL_USBVBUS_PLUGIN_HARDWARE,
				&plugin, 
				sizeof(plugin), 
				NULL, 
				0, 
				&unused, 
				NULL);
	if (ret == 0) {
		printf("DeviceIoControl failed: %ld",GetLastError());
		return -1;
	}
	return 0;
}

#ifdef DEBUG
static void ipusb_dump_header(struct ipusb_header *pdu)
{
	dbg_file("BASE: cmd %u seq %u devid %u dir %u ep %u\n",
			pdu->base.command,
			pdu->base.seqnum,
			pdu->base.devid,
			pdu->base.direction,
			pdu->base.ep);

	switch(pdu->base.command) {
		case IPUSB_CMD_SUBMIT:
			dbg_file("CMD_SUBMIT: x_flags %u x_len %u"
				" sf %u #p %u iv %u\n",
				pdu->u.cmd_submit.transfer_flags,
				pdu->u.cmd_submit.transfer_buffer_length,
				pdu->u.cmd_submit.start_frame,
				pdu->u.cmd_submit.number_of_packets,
				pdu->u.cmd_submit.interval
				);
				break;
		case IPUSB_CMD_UNLINK:
			dbg_file("CMD_UNLINK: seq %u\n", 
				pdu->u.cmd_unlink.seqnum);
			break;
		case IPUSB_RET_SUBMIT:
			dbg_file("RET_SUBMIT: st %d al %u sf %d #p %d ec %d\n",
					pdu->u.ret_submit.status,
					pdu->u.ret_submit.actual_length,
					pdu->u.ret_submit.start_frame,
					pdu->u.cmd_submit.number_of_packets,
					pdu->u.ret_submit.error_count);
			break;
		case IPUSB_RET_UNLINK:
			dbg_file("RET_UNLINK: status %d\n", 
				pdu->u.ret_unlink.status);
			break;
		default:
			/* NOT REACHED */
			dbg_file("UNKNOWN\n");
	}
}
#endif

struct fd_info {
	SOCKET sock;
	HANDLE dev;
};

static void correct_endian_basic(struct ipusb_header_basic *base, int send)
{
	if (send) {
		base->command	= htonl(base->command);
		base->seqnum	= htonl(base->seqnum);
		base->devid	= htonl(base->devid);
		base->direction	= htonl(base->direction);
		base->ep	= htonl(base->ep);
	} else {
		base->command	= ntohl(base->command);
		base->seqnum	= ntohl(base->seqnum);
		base->devid	= ntohl(base->devid);
		base->direction	= ntohl(base->direction);
		base->ep	= ntohl(base->ep);
	}
}

static void correct_endian_ret_submit(struct ipusb_header_ret_submit *pdu)
{
	pdu->status	= ntohl(pdu->status);
	pdu->actual_length = ntohl(pdu->actual_length);
	pdu->start_frame = ntohl(pdu->start_frame);
	pdu->number_of_packets = ntohl(pdu->number_of_packets);
	pdu->error_count = ntohl(pdu->error_count);
}

static void correct_endian_cmd_submit(struct ipusb_header_cmd_submit *pdu)
{
	pdu->transfer_flags	= ntohl(pdu->transfer_flags);
	pdu->transfer_buffer_length = ntohl(pdu->transfer_buffer_length);
	pdu->start_frame = ntohl(pdu->start_frame);
	pdu->number_of_packets = ntohl(pdu->number_of_packets);
	pdu->interval = ntohl(pdu->interval);
}

int ipusb_header_correct_endian(struct ipusb_header *pdu, int send)
{
	unsigned int cmd = 0;

	if (send)
		cmd = pdu->base.command;

	correct_endian_basic(&pdu->base, send);

	if (!send)
		cmd = pdu->base.command;

	switch (cmd) {
		case IPUSB_CMD_SUBMIT:
			correct_endian_cmd_submit(&pdu->u.cmd_submit);
			break;
		case IPUSB_RESET_DEV:
			break;
		case IPUSB_RET_SUBMIT:
			correct_endian_ret_submit(&pdu->u.ret_submit);
			break;
		default:
			/* NOTREACHED */
			printf("unknown command in pdu header: %d", cmd);
			return -1;
			//BUG();
	}
	return 0;
}

#define OUT_Q_LEN 256
static unsigned long out_q_seqnum_array[OUT_Q_LEN];

int record_out(long num)
{
	int i;
	for(i=0;i<OUT_Q_LEN;i++){
		if(out_q_seqnum_array[i])
			continue;
		out_q_seqnum_array[i]=num;
		return 1;
	}
	return 0;
}

int check_out(unsigned long num)
{
        int i;
	for(i=0;i<OUT_Q_LEN;i++){
		if(out_q_seqnum_array[i]!=num)
			continue;
		out_q_seqnum_array[i]=0;
		return 1;
	}
	return 0;
}

void fix_iso_desc_endian(char *buf, int num)
{
	struct ipusb_iso_packet_descriptor * ip_desc;
	int i;
	int all=0;
	ip_desc = (struct ipusb_iso_packet_descriptor *) buf;
	for(i=0;i<num;i++){
		ip_desc->offset = ntohl(ip_desc->offset);
		ip_desc->status = ntohl(ip_desc->status);
		ip_desc->length = ntohl(ip_desc->length);
		ip_desc->actual_length = ntohl(ip_desc->actual_length);
		all+=ip_desc->actual_length;
		ip_desc++;
	}
}

#ifdef DEBUG
void dbg_file(const char *fmt, ...)
{
	static FILE *fp=NULL;
	va_list ap;
	if(fp==NULL){
		fp=fopen("debug.log", "w");
	}
	if(NULL==fp)
		return;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fflush(fp);
	return;
}
#else
void dbg_file(const char *fmt, ...)
{
    //return;
}
#endif

int 
write_to_dev(char * buf,
	unsigned int buf_len, 
	unsigned int len, 
	SOCKET sockfd,
	HANDLE devfd, 
	OVERLAPPED *ov)
{
        unsigned int ret;
	unsigned long out=0, in_len, iso_len;
	struct ipusb_header * u = (struct ipusb_header *)buf;

	if(len!=sizeof(*u)){
		printf("read from sock ret %d not equal a ipusb_header", len);
#if 0
		ipusb_dump_buffer(buf,len);
#endif
		return -1;
	}
	if(ipusb_header_correct_endian(u, 0)<0)
                return -1;

        dbg_file("recv seq %d\n", u->base.seqnum);

#ifdef DEBUG
	ipusb_dump_header(u);
#endif

	if(check_out(htonl(u->base.seqnum)))
		in_len=0;
	else
		in_len=u->u.ret_submit.actual_length;

	iso_len = u->u.ret_submit.number_of_packets
			* sizeof(struct ipusb_iso_packet_descriptor);

	if(in_len==0&&iso_len==0){
		ret=WriteFile(devfd, (char *)u, sizeof(*u), &out, ov);
		if(!ret||out!=sizeof(*u)){
			printf("last error:%ld",GetLastError());
			printf("out:%ld ret:%d",out,ret);
			printf("write dev failed");
			return -1;
		}
		return 0;
	}
	len = sizeof(*u) + in_len + iso_len;
	if(len>buf_len){
		printf("too big len %d %ld %ld", len, in_len,iso_len);
		return -1;
	}
	ret=ipusb_recv(sockfd, buf+sizeof(*u),
		in_len+iso_len);
	if(ret != in_len + iso_len){
		printf("recv from sock failed %d %ld",
				ret,
				in_len + iso_len);
		return -1;
	}

	if(iso_len)
                fix_iso_desc_endian(buf + sizeof(*u) + in_len,
                                u->u.ret_submit.number_of_packets
                                );
	ret=WriteFile(devfd, buf, len, &out, ov);
	if(!ret||out!=len){
		printf("last error:%ld\n",GetLastError());
		printf("out:%ld ret:%d len:%d\n",out,ret,len);
		printf("write dev failed");
		return -1;
	}
	return 0;
}

int sock_read_async(SOCKET sockfd,
                HANDLE devfd,
                OVERLAPPED *ov_sock,
                OVERLAPPED *ov_dev,
                char *sock_read_buf)
{
	int ret, err=0;
	unsigned long len;
	do {
		ret = ReadFile((HANDLE)sockfd,  sock_read_buf,
			sizeof(struct ipusb_header), &len, ov_sock);
		if (!ret)
			err=GetLastError();

		if(err==ERROR_IO_PENDING)
			return 0;

		if(err) {
			printf("read:%d err:%d\n",ret, err);
			return -1;
		}

		if (len!=sizeof(struct ipusb_header))
		{
			err=GetLastError();
			printf("incomplete header %d %d\n",ret,err);
		}

		dbg_file("Bytes read from socket synchronously: %d\n",len);
		ret = write_to_dev(sock_read_buf, BIG_SIZE, len,
				sockfd, devfd, ov_dev);
		if(ret<0)
			return -1;
	}while(1);
}

int sock_read_completed(SOCKET sockfd,
                        HANDLE devfd,
                        OVERLAPPED *ov_sock,
                        OVERLAPPED *ov_dev,
                        char *sock_read_buf)
{

	int ret;
	unsigned long len;
	ret = GetOverlappedResult((HANDLE)sockfd, ov_sock, &len, FALSE);
	if(!ret){
		printf("get overlapping failed: %ld", GetLastError());
		return -1;
	}
	dbg_file("Bytes read from socket asynchronously: %d\n",len);
	ret = write_to_dev(sock_read_buf, BIG_SIZE, len, sockfd, devfd, ov_dev);
	if(ret<0)
		return -1;
        return sock_read_async(sockfd, devfd, ov_sock, ov_dev, sock_read_buf);
}

int write_to_sock(char *buf, unsigned int len, SOCKET sockfd)
{
	struct ipusb_header *u;
        unsigned int ret;
	unsigned long out_len, iso_len;

	u=(struct ipusb_header *)buf;

	if(len<sizeof(*u)){
		printf("read dev len: %d\n", len);
		return -1;
	}
	if(!u->base.direction)
		out_len=ntohl(u->u.cmd_submit.transfer_buffer_length);
	else
		out_len=0;
	if(u->u.cmd_submit.number_of_packets)
		iso_len=sizeof(struct ipusb_iso_packet_descriptor)*
			ntohl(u->u.cmd_submit.number_of_packets);
	else
		iso_len=0;
	if(len!= sizeof(*u) + out_len + iso_len){
		printf("read dev len:%d out_len:%ld"
				    "iso_len: %ld\n",
			len, out_len, iso_len);
		return -1;
	}
	if(!u->base.direction&&!record_out(u->base.seqnum)){
		printf("out q full");
		return -1;
	}
	dbg_file("send seq:%lu\r", ntohl(u->base.seqnum));
	dbg("Send sequence: %lu\n",  ntohl(u->base.seqnum));

	ret=ipusb_send(sockfd, buf, len);
	if(ret!=len){
		printf("send sock len:%d, ret:%d\n", len, ret);
		return -1;
	}
	#ifdef DEBUG
	{
		struct ipusb_header cu;
		memcpy(&cu,u,sizeof(struct ipusb_header));
		ipusb_header_correct_endian(&cu,0);
		ipusb_dump_header(&cu);
	}
	#endif
	return 0;
}

int 
dev_read_async(HANDLE devfd, SOCKET sockfd, OVERLAPPED *ov, char *dev_read_buf)
{
	int ret, x;
	unsigned long len;

	do {
		len=0;
		ret = ReadFile(devfd, dev_read_buf, BIG_SIZE, &len, ov);
		if(!ret &&  (x=GetLastError())!=ERROR_IO_PENDING) {
			printf("read:%d x:%d\n",ret, x);
			return -1;
		}
		if(!ret) 
			return 0;

		ret = write_to_sock(dev_read_buf, len, sockfd);
		if(ret<0)
			return -1;
	} while(1);
}

int dev_read_completed(HANDLE devfd,
                        SOCKET sockfd,
                        OVERLAPPED *ov,
                        char *dev_read_buf)
{
	int ret;
	unsigned long len;
	ret = GetOverlappedResult(devfd, ov, &len, FALSE);
	if(!ret){
		printf("get overlapping failed: %ld", GetLastError());
		return -1;
	}
	ret = write_to_sock(dev_read_buf, len, sockfd);
	if(ret<0)
		return -1;
        return dev_read_async(devfd, sockfd, ov, dev_read_buf);
}


void ipusb_vbus_forward(SOCKET sockfd, HANDLE devfd, volatile bool *stop_cond)
{
	HANDLE ev[3];
	OVERLAPPED ov[3];
	int ret;
	int i;
	int err=0;

        char *dev_read_buf = (char *)malloc(BIG_SIZE);
        char *sock_read_buf= (char *)malloc(BIG_SIZE);

        if(dev_read_buf == NULL || sock_read_buf==NULL){
		printf("cannot allocate buffers");
		return;
	}

	for(i=0;i<3;i++){
		ev[i]=CreateEvent(NULL, FALSE, FALSE, NULL);
		if(NULL==ev[i]){
			printf("cannot create new events");
			return;
		}
		ov[i].Offset=ov[i].OffsetHigh=0;
		ov[i].hEvent=ev[i];
	}

        dev_read_async(devfd, sockfd, &ov[0], dev_read_buf);
        sock_read_async(sockfd, devfd, &ov[1], &ov[2], sock_read_buf);

	do {
		dbg_file("wait\n");
                ret =  WaitForMultipleObjects(2, ev, FALSE, 200);

		switch (ret) {
		case WAIT_TIMEOUT:
			break;
		case WAIT_OBJECT_0:
                        err=dev_read_completed(devfd, 
						sockfd, 
						&ov[0], 
						dev_read_buf
						);
			break;
		case WAIT_OBJECT_0 + 1:
                        err=sock_read_completed(sockfd, 
						devfd, 
						&ov[1], 
						&ov[2], 
						sock_read_buf
						);
			break;
		default:
			printf("unknown ret %d\n",ret);
			err=ret;
			break;
		}
       // } while(!err && !(*stop_cond));
		 } while(!err);
	free(dev_read_buf);
	free(sock_read_buf);
	return;
}
