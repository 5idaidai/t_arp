#include <stdlib.h>
#include <stdio.h>
#include "pcap.h"
#include "remote-ext.h"
#include <process.h>

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"Ws2_32.lib")

#define ETH_IP       0x0800
#define ETH_ARP      0x0806
#define ARP_REQUEST  0x0001
#define ARP_REPLY    0x0002
#define ARP_HARDWARE 0x0001
#define max_num_adapter  10

//28字节ARP帧结构
struct arp_head
{
    unsigned short hardware_type;    //硬件类型
    unsigned short protocol_type;    //协议类型
    unsigned char hardware_add_len; //硬件地址长度
    unsigned char protocol_add_len; //协议地址长度
    unsigned short operation_field; //操作字段
    unsigned char source_mac_add[6]; //源mac地址
    unsigned long source_ip_add;    //源ip地址
    unsigned char dest_mac_add[6]; //目的mac地址
    unsigned long dest_ip_add;      //目的ip地址
};
//14字节以太网帧结构
struct ethernet_head
{
    unsigned char dest_mac_add[6];    //目的mac地址
    unsigned char source_mac_add[6]; //源mac地址
    unsigned short type;              //帧类型
};
 
//arp最终包结构
struct arp_packet
{
    ethernet_head eh;
    arp_head ah;
};

struct pc
{
	unsigned long ip;
	unsigned char mac[6];
}pcGroup[255];

u_char selfMac[6]={0};
u_long myip;
pcap_t *adhandle;
u_long firstip,secondip;
unsigned int HostNum = 0;
int flag = FALSE;

void usage()
{   
	printf("\nUsage: T-ARP  [-m|-a|-s|-r]  firstip  secondip  \n\n");
    printf("    1> You must have installed the winpcap_2.3 or winpcap_3.0_alpha\n");
    printf("    2> HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\IPEnableRouter==0x1\n\n");
    return ;
}

void GetlivePc();

int OpenIf(){	
    int j=0,inum = 0;
	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_if_t *alldevs;
    pcap_if_t *d;

    /* 获取接口列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* 不需要远程认证 */, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

	for(d= alldevs; d != NULL; d= d->next)
    {
        printf("%d. %s", ++j, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

	printf("请选择网卡(1-%d)：",j);
    scanf_s("%d", &inum);
    if(inum < 1 || inum > j)
    {
        printf("\nInterface number out of range.\n");
        /* 释放设备接口列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* 转到所选的接口 */
    for(d=alldevs, j=0; j< inum-1 ;d=d->next, j++);


	 /* 打开发送数据报的适配器接口*/
    if ( (adhandle= pcap_open(d->name,            // 适配器名称
                        100,                // 所要捕获的数据包大小(仅捕获前个字节)
                        PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
                        1000,               // 超时时间
                        NULL,               // 远程认证
                        errbuf              // 错误缓冲区
                        ) ) == NULL)
    {
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        return 0;
    }
	else return -1;
}

//获得自己主机的MAC地址
int GetSelfMac()
{
	struct pcap_pkthdr * pkt_header;
    const u_char * pkt_data;
	unsigned char sendbuf[42]={0};//arp包结构大小
    int i = -1;
    int res;
    ethernet_head eh;
    arp_head ah;
 
    memset(eh.dest_mac_add,0xff,6);
    memset(eh.source_mac_add,0x0f,6);
 
    memset(ah.source_mac_add,0x0f,6);
    memset(ah.dest_mac_add,0x00,6);
 
    eh.type = htons(ETH_ARP);
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_add_len = 6;
    ah.protocol_add_len = 4;
    ah.source_ip_add = inet_addr("219.219.71.230"); //随便设的请求方ip
	//printf("%x\n",ah.source_ip_add);
    ah.operation_field = htons(ARP_REQUEST);
    // unsigned long ip;
    // ip = ntohl(inet_addr("192.168.1.101"));
    // ah.dest_ip_add =htonl(ip + loop);
    ah.dest_ip_add = inet_addr("192.168.1.202");
	//printf("%x\n",ah.dest_ip_add);
    memset(sendbuf,0,sizeof(sendbuf));
	memcpy(sendbuf,&eh,sizeof(eh));
    memcpy(sendbuf+sizeof(eh),&ah,14);
	memcpy(sendbuf+sizeof(eh)+14,&ah.source_ip_add,10);
	memcpy(sendbuf+sizeof(eh)+24,&ah.dest_ip_add,4);

	if(pcap_sendpacket(adhandle,sendbuf,42)==0)
    {
    //   printf("\nPacketSend succeed\n");
    }
    else
    {
         printf("PacketSendPacket in getmine Error: %d\n",GetLastError());
         return 0;
    }
 
    while((res = pcap_next_ex(adhandle,&pkt_header,&pkt_data)) > 0)
    {
		if(*(unsigned short *)(pkt_data+12) == htons(ETH_ARP)&&
        *(unsigned short*)(pkt_data+20) == htons(ARP_REPLY)&&
        *(unsigned long*)(pkt_data+38) == inet_addr("219.219.71.230"))
        {
            printf("我的网卡地址是："); 
            for(i=0; i<5; i++)
            {
                selfMac[i] = *(unsigned char*)(pkt_data+22+i);				
				printf("%x:",selfMac[i]);
            }
            selfMac[i] = *(unsigned char*)(pkt_data+22+i);	
			printf("%x\n",selfMac[i]);
			myip = *(unsigned long *)(pkt_data+28);
			//printf("myip=%u",myip);
            break;			
        }
    }
	
	if(res == 0){
        printf("Get the packet timeout,please confirm whether the network connect!\n");
        return -1;
    }

	if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }
	if(i==6) return 1;
    else return 0;
}

//向局域网内的所有可能的IP地址发送ARP请求包线程
 
void sendArpPacket()
{ 
    unsigned char sendbuf[42];//arp包结构大小
    unsigned long ip;
	const char iptosendh[20] = {0};
    ethernet_head eh;
    arp_head ah;
    memset(eh.dest_mac_add,0xff,6);
    memcpy(eh.source_mac_add,selfMac,6);
 
    memcpy(ah.source_mac_add,selfMac,6);
    memset(ah.dest_mac_add,0x00,6);
 
    eh.type = htons(ETH_ARP);
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_add_len = 6;
    ah.protocol_add_len = 4;
    ah.operation_field = htons(ARP_REQUEST);
    ah.source_ip_add = myip;
 
    for (unsigned long i=0; i<HostNum; i++)
    {
        ip = firstip;
		ah.dest_ip_add =htonl(htonl(ip) + i);
        memset(sendbuf,0,sizeof(sendbuf));
        memcpy(sendbuf,&eh,sizeof(eh));
        memcpy(sendbuf+sizeof(eh),&ah,14);
	    memcpy(sendbuf+sizeof(eh)+14,&ah.source_ip_add,10);
	    memcpy(sendbuf+sizeof(eh)+24,&ah.dest_ip_add,4);
        if(pcap_sendpacket(adhandle,sendbuf,42)==0)
        {
         // printf("\nRequest Packet succeed\n");
        }
        else
        {
            printf("Request Packet in getmine Error: %d\n",GetLastError());
        }
		GetlivePc();
    }
    Sleep(1000);
    flag = TRUE;
}

//接收ARP响应线程，分析数据包后即可获得活动的主机IP地址等
 
void GetlivePc()
{
    //pcap_t *p=(pcap_t *)lpParameter;
    int res;
	int aliveNum=0;
 
    // arp_head ah;
    struct pcap_pkthdr *pkt_header;
    const u_char * pkt_data;
    unsigned char tempMac[6];
    /*while (true)
    {
        if(flag)
        {
            printf("扫描完毕，监听线程退出!\n");
            //ExitThread(0);
            break;
        }*/
 
        if ((res = pcap_next_ex(adhandle,&pkt_header,&pkt_data)) > 0)
        { 
            //printf("%x",ntohs(*(unsigned short *)(pkt_data+12)));
            if(*(unsigned short *)(pkt_data+12) == htons(ETH_ARP))
            {
				arp_packet *recv = (arp_packet*)pkt_data;
				//printf("%x\n",recv->ah.source_ip_add);
				recv->ah.source_ip_add = *(unsigned long *)(pkt_data+28);
                if(*(unsigned short *)(pkt_data+20) == htons(ARP_REPLY))
                {
                    printf("捕获到arp应答包：\n");
                    printf("IP地址：%d.%d.%d.%d---------->mac地址：",
                    recv->ah.source_ip_add&255, recv->ah.source_ip_add>>8&255,
                    recv->ah.source_ip_add>>16&255, recv->ah.source_ip_add>>24&255);
                    pcGroup[aliveNum].ip = *(unsigned long *)(pkt_data+28);
                    memcpy(pcGroup[aliveNum].mac,(pkt_data+22),6);
                    aliveNum++;
                    for(int i=0; i<6; i++)
                    {
                        tempMac[i] = *(unsigned char*)(pkt_data+22+i);
                        printf("%02x",tempMac[i]);
                    }
                    printf("\n");
                }
            }
        }
        Sleep(50);
    //}
}

int main(int argc,char *argv[]){
	if(argc!=3)
    {
        usage();
        return -1;
    }
	//HANDLE hThread1,hThread2;
	firstip = inet_addr(argv[1]);
	secondip = inet_addr(argv[2]);
	HostNum = htonl(secondip) - htonl(firstip) + 1;
	//printf("%x %x %d",htonl(secondip),htonl(firstip),HostNum);
	OpenIf();
	GetSelfMac();
	sendArpPacket();
	return 1;
}