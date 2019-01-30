#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <process.h>
#include <windows.h>
#include <string.h>
#include <ws2ipdef.h>
#include "Modbus_Header.h"
#include "Modbus_Config.h"
using namespace std;
//解决LNK2019错误
#pragma comment(lib,"ws2_32.lib")

extern SOCKET TCP_S;
extern ModbusPacket *Connect_Packet;
extern char str_ip[18];
extern char str_port[6];
extern char pwd[9];
extern char pid[11];
extern FILE *fp;
extern unsigned int Rcev_Total_Numbers;
extern char ph[12];
char cpath[28] = {'\0'};

Buffer* NewBuffer(void)
{
    Buffer* buf = (Buffer*)malloc(sizeof(Buffer));
    buf->_data = (uint8*)malloc(sizeof(uint8) * BUFFER_SIZE);
    buf->_len = 0;
    return buf;
}

void DeleteBuffer(Buffer** buf)
{
    uint8* pdata = (*buf)->_data;
    free(pdata);
    free(*buf);
    *buf = 0;
}

int32 WriteByte(Buffer* buf, uint8 byte)
{
    buf->_data[buf->_len] = byte;
    buf->_len++;
    return 0;
}

int32 WriteBytes(Buffer* buf, const void* bytes, uint32 count)
{
    memcpy(buf->_data + buf->_len, bytes, count);
    buf->_len += count;
	//printf("count:%d\n",count);
    return 0;
}

int32 WriteUint16(Buffer* buf, uint16 val)
{
    return WriteByte(buf, MOSQ_MSB(val))
        || WriteByte(buf, MOSQ_LSB(val));
}

unsigned int CRC16(unsigned char *puchMsg,unsigned int  usDataLen)
{
    /*用于CRC校验*/
    const  int auchCRCHi[256]={
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
    0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01,
    0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81,
    0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01,
    0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
    0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01,
    0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
    0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01,
    0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
    0x40};
    const  int auchCRCLo[256]={
    0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06, 0x07, 0xC7, 0x05, 0xC5, 0xC4,
    0x04, 0xCC, 0x0C, 0x0D, 0xCD, 0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
    0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A, 0x1E, 0xDE, 0xDF, 0x1F, 0xDD,
    0x1D, 0x1C, 0xDC, 0x14, 0xD4, 0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
    0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3, 0xF2, 0x32, 0x36, 0xF6, 0xF7,
    0x37, 0xF5, 0x35, 0x34, 0xF4, 0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
    0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29, 0xEB, 0x2B, 0x2A, 0xEA, 0xEE,
    0x2E, 0x2F, 0xEF, 0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
    0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60, 0x61, 0xA1, 0x63, 0xA3, 0xA2,
    0x62, 0x66, 0xA6, 0xA7, 0x67, 0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
    0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68, 0x78, 0xB8, 0xB9, 0x79, 0xBB,
    0x7B, 0x7A, 0xBA, 0xBE, 0x7E, 0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
    0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71, 0x70, 0xB0, 0x50, 0x90, 0x91,
    0x51, 0x93, 0x53, 0x52, 0x92, 0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
    0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B, 0x99, 0x59, 0x58, 0x98, 0x88,
    0x48, 0x49, 0x89, 0x4B, 0x8B, 0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
    0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42, 0x43, 0x83, 0x41, 0x81, 0x80,
    0x40};
    unsigned char uchCRCHi,uchCRCLo;
    unsigned char uIndex=0 ; 
    unsigned char tempp=0;
    unsigned int CRCHL=0;
    uchCRCHi=0xFF ;            
    uchCRCLo=0xFF ;
    tempp=0;                       
    while(usDataLen--)              
    {
        uIndex=uchCRCHi^*puchMsg++ ; 
        tempp++;
        uchCRCHi=uchCRCLo^auchCRCHi[uIndex] ;
        uchCRCLo=auchCRCLo[uIndex] ;
    }
    CRCHL=uchCRCHi;
    CRCHL=CRCHL<<8;
    CRCHL|=uchCRCLo;
    return CRCHL;
}

ModbusPacket *PacketConnect(const char *phone, int phoneLen, const char *pwd, int pwdLen, const char* pid, int pidLen)
{
	ModbusPacket* pkg = NULL;
	unsigned char type[11] = "type";
	unsigned char name[9] = "name";
    pkg = NewBuffer();
	WriteBytes(pkg, type, sizeof(type));
	WriteBytes(pkg, name, sizeof(name));
	WriteBytes(pkg, phone, phoneLen);
	WriteBytes(pkg, pwd, pwdLen);
	WriteBytes(pkg, pid, pidLen);
	return pkg;
}

ModbusPacket *PacketPing(void)
{
    ModbusPacket* pkg = NULL;
    pkg = NewBuffer();
	WriteByte(pkg, 0);
	WriteByte(pkg, 0);
	return pkg;

}

void Print_Log_Time(void)
{
	time_t Timestamp;
	struct tm *Time;
	char *Week_Day[] = { "星期日", "星期一", "星期二", "星期三", "星期四", "星期五", "星期六" };
	time(&Timestamp);
	Time = localtime(&Timestamp);
	//localtime_s(Time, &Timestamp);
	printf("%d-%02d-%02d", Time->tm_year + 1900, Time->tm_mon + 1, Time->tm_mday);
	printf(" %s %02d:%02d:%02d:", Week_Day[Time->tm_wday], Time->tm_hour, Time->tm_min, Time->tm_sec);
	if(fp)
	{
		fprintf(fp,"%d-%02d-%02d", Time->tm_year + 1900, Time->tm_mon + 1, Time->tm_mday);
		fprintf(fp," %s %02d:%02d:%02d:", Week_Day[Time->tm_wday], Time->tm_hour, Time->tm_min, Time->tm_sec);
	}
}

void Print_Log(void)
{
	char         ch;
	if(strlen(cpath) == 0)
	{
		time_t Timestamp;
		struct  tm *Time;
		time(&Timestamp);
		int  i, j, ivalue;
		int times = 1000;
		Time = localtime(&Timestamp);
		int itime[] = {Time->tm_mon + 1, Time->tm_mday, Time->tm_hour, Time->tm_min, Time->tm_sec};
		memset(cpath, 0, sizeof(cpath));
		cpath[0] = 'L';
		cpath[1] = 'o';
		cpath[2] = 'g';
		cpath[strlen(cpath)] = '-';
		ivalue = Time->tm_year + 1900;
		while(times != 0)
		{
			cpath[strlen(cpath)] = ivalue/times + 48;
			ivalue %= times;
			times /= 10;
		}
		for(i = 0; i < 5; i++)
		{
			cpath[strlen(cpath)] = '-';
			ivalue = itime[i];
			times = 10;
			while(times != 0)
			{
				cpath[strlen(cpath)] = ivalue/times + 48;
				ivalue %= times;
				times /= 10;
			}
		}
		cpath[strlen(cpath)] = '.';
		cpath[strlen(cpath)] = 'l';
		cpath[strlen(cpath)] = 'o';
		cpath[strlen(cpath)] = 'g';
	}
	fp = fopen(cpath, "a+");
	if(fp == NULL)
	{
		perror("文件打开失败！");
	}
}

unsigned short StrTOShort(char *str_port)
{
	int U_Short_Port;
	bool  flag=false;
	while(*str_port)
	{
		if(flag)
		{
			U_Short_Port*=10;
			U_Short_Port+=(int)(*str_port)-48;
		}
		else
		{
			U_Short_Port=(int)(*str_port)-48;
			flag=true;
		}
		str_port++;
	}
	return((unsigned short)U_Short_Port);
}

void Recv_Cmd_Function(char *CMD, int CMD_Len)
{
	char *heart_signal_packet="心跳";
	int          i,j,k = -1,CMD_NO=0;
	INT                    ret,bytes;
	PModbusRecvPacket    MBRP = NULL;
	uint16          Rand_No, CRC = 0;
	unsigned int           Count = 0;
	CMD_NO = CMD_Len/8;
	for(i=0;i<CMD_NO;i++)
	{
		Print_Log();
		#ifdef debug
		for(j=0;j<2;j++)
		{
			printf("%02x ",(unsigned char)(*(CMD+(i*8)+j)));
			fprintf(fp,"%02x ",(unsigned char)(*(CMD+(i*8)+j)));
		}
		printf("\n");
		fprintf(fp,"\n");
		#endif
		MBRP = (PModbusRecvPacket)NewBuffer();
		bytes=WriteBytes(MBRP,CMD+(i*8),2);
		#ifdef debug
		for(j=0;j<2;j++)
		{
			printf("%02x ",(unsigned char)MBRP->_data[j]);
			fprintf(fp,"%02x ",(unsigned char)MBRP->_data[j]);
		}
		printf("\n");
		fprintf(fp,"\n");
		#endif
		if(bytes<0)
		{
			printf("重机地址或功能代码数据写入失败!\n");
			bytes = send(TCP_S, heart_signal_packet,strlen(heart_signal_packet), 0);
			fprintf(fp,"重机地址或功能代码数据写入失败!\n");
			Print_Log_Time();
			if(bytes>0)
			{
				printf("心跳包发送成功\n心跳包内容为:");
				fprintf(fp,"心跳包发送成功\n心跳包内容为:");
				for(j=0;j<bytes;j++)
				{
					printf("%02x ",heart_signal_packet[j]);
					fprintf(fp,"%02x ",heart_signal_packet[j]);
				}
				printf("\n");
				fprintf(fp,"\n");
			}
			else
			{
				printf("心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
				fprintf(fp,"心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
			}
			fclose(fp);
		}
		else
		{
			bytes=WriteByte(MBRP,(uint8)((*(CMD+(i*8)+5))<<1));
			if(bytes<0)
			{
				printf("数据长度写入失败!\n");
				fprintf(fp,"数据长度写入失败!\n");
				bytes = send(TCP_S, heart_signal_packet,strlen(heart_signal_packet), 0);
				Print_Log_Time();
				if(bytes>0)
				{
					printf("心跳包发送成功\n心跳包内容为:");
					fprintf(fp,"心跳包发送成功\n心跳包内容为:");
					for(j=0;j<bytes;j++)
					{
						printf("%02x ",heart_signal_packet[j]);
						fprintf(fp,"%02x ",heart_signal_packet[j]);
					}
					printf("\n");
					fprintf(fp,"\n");
				}
				else
				{
					printf("心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
					fprintf(fp,"心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
				}
				fclose(fp);
			}
			else
			{
				for(j=0;j<(int)((*(CMD+(i*8)+5)));j++)
				{
					Rand_No=rand() % 65536;
					printf("生成的第%d个随机数为:%d\n",j+1,Rand_No);
					fprintf(fp,"生成的第%d个随机数为:%d\n",j+1,Rand_No);
					bytes=WriteUint16(MBRP,Rand_No);
					if(bytes<0)
					{
						printf("第%d个数据写入失败!\n",j+1);
						fprintf(fp,"第%d个数据写入失败!\n",j+1);
						bytes = send(TCP_S, heart_signal_packet,strlen(heart_signal_packet), 0);
						Print_Log_Time();
						if(bytes>0)
						{
							printf("心跳包发送成功\n心跳包内容为:");
							fprintf(fp,"心跳包发送成功\n心跳包内容为:");
							for(k=0;k<bytes;k++)
							{
								printf("%02x ",heart_signal_packet[k]);
								fprintf(fp,"%02x ",heart_signal_packet[k]);
							}
							printf("\n");
							fprintf(fp,"\n");
						}
						else
						{
							printf("心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
							fprintf(fp,"心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
						}
						fclose(fp);
						break;
					}
				}
				if(j==(int)(*(CMD+(i*8)+5)))
				{
					CRC=(uint16)CRC16(MBRP->_data,MBRP->_len);
					if(CRC)
					{
						bytes=WriteUint16(MBRP,CRC);
						if(bytes<0)
						{
							printf("校验码写入失败!\n");
							fprintf(fp,"校验码写入失败!\n");
							bytes = send(TCP_S, heart_signal_packet,strlen(heart_signal_packet), 0);
							Print_Log_Time();
							if(bytes>0)
							{
								printf("心跳包发送成功\n心跳包内容为:");
								fprintf(fp,"心跳包发送成功\n心跳包内容为:");
								for(j=0;j<bytes;j++)
								{
									printf("%02x ",heart_signal_packet[j]);
									fprintf(fp,"%02x ",heart_signal_packet[j]);
								}
								printf("\n");
								fprintf(fp,"\n");
							}
							else
							{
								printf("心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
								fprintf(fp,"心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
							}
							fclose(fp);
						}
						else
						{
							bytes = send(TCP_S, (char *)MBRP->_data,(int)MBRP->_len, 0);
							Print_Log_Time();
							if(bytes>0)
							{
								Rcev_Total_Numbers++;
								
								printf("发送%d字节\n发送内容为:", bytes);
								fprintf(fp,"发送%d字节\n发送内容为:", bytes);
								for (j = 0; j < bytes; j++)
								{
									printf("%02x ", (unsigned char)MBRP->_data[j]);
									fprintf(fp,"%02x ", (unsigned char)MBRP->_data[j]);
								}
								printf("\n");
								fprintf(fp,"\n");
							}
							else
							{
								printf("数据发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
								fprintf(fp,"数据发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
							}
							fclose(fp);
						}
					}
					else
					{
						printf("校验码生成失败!\n");
						fprintf(fp,"校验码生成失败!\n");
						bytes = send(TCP_S, heart_signal_packet,strlen(heart_signal_packet), 0);
						Print_Log_Time();
						if(bytes>0)
						{
							printf("心跳包发送成功\n心跳包内容为:");
							fprintf(fp,"心跳包发送成功\n心跳包内容为:");
							for(j=0;j<bytes;j++)
							{
								printf("%02x ",heart_signal_packet[j]);
								fprintf(fp,"%02x ",heart_signal_packet[j]);
							}
							printf("\n");
							fprintf(fp,"\n");
						}
						else
						{
							printf("心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
							fprintf(fp,"心跳包发送失败,SOCKET_ERROR为:%d\n",WSAGetLastError());
						}
						fclose(fp);
					}
				}
			}
		}
		DeleteBuffer(&MBRP);
	}
}

SOCKET SocketConnect(char *ip,char *port)
{
	SOCKET      TCP_Client;
	WSADATA        wsaData;
	INT                ret;
	unsigned short    Port;
	int Recv_Timeout = 240000;
	if (ret = WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("Winsock DLL 加载失败,错误代码为：%d\n", ret);
		system("pause");
		return(0);
	}
	TCP_Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (TCP_Client == INVALID_SOCKET)
	{
		printf("创建套接字失败！");
		system("pause");
		return(0);
	}
	setsockopt(TCP_Client, SOL_SOCKET, SO_RCVTIMEO, (char *)&Recv_Timeout ,sizeof(int));
	SOCKADDR_IN Cli_Addr;
	Cli_Addr.sin_family = AF_INET;
	Port=StrTOShort(port);
	Cli_Addr.sin_port = htons(Port);
	Cli_Addr.sin_addr.S_un.S_addr = inet_addr(ip);
	printf("IP为:%s\n端口为:%d\n",ip,(int)Port);
	if(fp)
	{
		fprintf(fp,"IP为:%s\n端口为:%d\n",ip,(int)Port);
	}
	int TCP_Connect;
	TCP_Connect = connect(TCP_Client, (sockaddr *)&Cli_Addr, sizeof(Cli_Addr));
	if (TCP_Connect == SOCKET_ERROR)
	{
		printf("链接失败！");
		system("pause");
		return(0);
	}
	return (TCP_Client);
}

unsigned __stdcall SendHeartSignalThreadFunc(void* pArguments)
{
	char *heart_signal_packet="心跳";
	int                            i;
	//char heart_signal_packet[5]={'\x00','\x00','\x00','\x00','\0'};
	INT                    ret,bytes;
	char             Recv_Data[1024];
	//Print_Log_Time();
	//printf("发送心跳包线程已启动！\n");
	while (1)
	{
		Sleep(1000);
		ret = recv(TCP_S, Recv_Data, 1024, 0);
		Print_Log();
		if (ret > 0)
		{
			Print_Log_Time();
			printf("收到%d字节\n收到内容为:", ret);
			fprintf(fp,"收到%d字节\n收到内容为:", ret);
			for (i = 0; i < ret; i++)
			{
				printf("%02x ", (unsigned char)Recv_Data[i]);
				fprintf(fp,"%02x ", (unsigned char)Recv_Data[i]);
			}
			printf("\n");
			fprintf(fp,"\n");
			fclose(fp);
			Recv_Cmd_Function(Recv_Data,ret);
		}
		else
		{
			Print_Log_Time();
			printf("平台在4分钟内未下发数据\n");
			fprintf(fp,"平台在4分钟内未下发数据\n");
			bytes = send(TCP_S, heart_signal_packet,strlen(heart_signal_packet), 0);
			if(bytes > 0)
			{
				Print_Log_Time();
				printf("发送%d字节心跳包数据\n发送内容为:",bytes);
				fprintf(fp,"发送%d字节心跳包数据\n发送内容为:",bytes);
				for (int i = 0; i < bytes; i++)
				{
					printf("%02x ", (unsigned char)heart_signal_packet[i]);
					fprintf(fp,"%02x ", (unsigned char)heart_signal_packet[i]);
				}
				printf("\n");
				fprintf(fp,"\n");
			}
			else
			{
				Print_Log_Time();
				printf("检测到设备与平台已断开连接,现在进行重连......\n");
				fprintf(fp,"检测到设备与平台已断开连接,现在进行重连......\n");
				TCP_S = SocketConnect(str_ip,str_port);
				Connect_Packet = NewBuffer();
				Connect_Packet = PacketConnect(ph,sizeof(ph),pwd,sizeof(pwd),pid,sizeof(pid));
				bytes = send(TCP_S, (char *)Connect_Packet->_data,(int)Connect_Packet->_len, 0);
				Print_Log_Time();
				if (bytes == (int)Connect_Packet->_len)
				{
					printf("重连成功！\n");
					fprintf(fp,"重连成功！\n");
				}
				else
				{
					printf("重连失败！\n");
					fprintf(fp,"重连失败！\n");
				}
				DeleteBuffer(&Connect_Packet);
			}
			fclose(fp);
		}
	}
	_endthreadex(0);
	return(0);
}

bool String_match(char *str_src,char *str_dst)
{
	if((!str_src)||(!str_dst))
	{
		return (false);
	}
	while(*str_src)
	{
		if((*str_dst)!=(*str_src))
		{
			return (false);
		}
		str_src++;
		str_dst++;
	}
	return (true);
}

void Read_Configure_Info(void)
{
	FILE                *fp;
	char    Str[30] = {'0'};
	char *s = "Effective=1";
	int               i = 0;
	fp = fopen("Initialization.ini","r+");
	if(!fp)
	{
		return;
	}
	fgets(Str,30,fp);
	if(String_match(s,Str))
	{
		if(!feof(fp))
		{
			memset(Str,0,sizeof(Str));
			fgets(Str,30,fp);
			while(Str[i]!='=')
			{
				i++;
			}
			memset(str_ip,0,sizeof(str_ip));
			memcpy(str_ip,Str+i+1,strlen(Str+i+1)-1);
			if(!feof(fp))
			{
				memset(Str,0,sizeof(Str));
				i = 0;
				fgets(Str,30,fp);
				while(Str[i]!='=')
				{
					i++;
				}
				memset(str_port,0,sizeof(str_port));
				memcpy(str_port,Str+i+1,strlen(Str+i+1)-1);
				if(!feof(fp))
				{
					memset(Str,0,sizeof(Str));
					i = 0;
					fgets(Str,30,fp);
					while(Str[i]!='=')
					{
						i++;
					}
					memset(ph,0,sizeof(ph));
					memcpy(ph,Str+i+1,strlen(Str+i+1)-1);
					if(!feof(fp))
					{
						memset(Str,0,sizeof(Str));
						i = 0;
						fgets(Str,30,fp);
						while(Str[i]!='=')
						{
							i++;
						}
						memset(pwd,0,sizeof(pwd));
						memcpy(pwd,Str+i+1,strlen(Str+i+1)-1);
						if(!feof(fp))
						{
							memset(Str,0,sizeof(Str));
							i = 0;
							fgets(Str,30,fp);
							while(Str[i]!='=')
							{
								i++;
							}
							memset(pid,0,sizeof(pid));
							if(Str[strlen(Str)-1]=='\n')
							{
								memcpy(pid,Str+i+1,strlen(Str+i+1)-1);
							}
							else
							{
								memcpy(pid,Str+i+1,strlen(Str+i+1));
							}
						}
					}
				}
			}
		}
	}
	fclose(fp);
}
