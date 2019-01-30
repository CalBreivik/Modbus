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

SOCKET TCP_S;
ModbusPacket *Connect_Packet = NULL;
char str_ip[18] = "117.187.200.10";
char str_port[6] = "987";
char pwd[9] = "qazwsx";
char pid[11] = "20000056";
FILE *fp = NULL;
unsigned int Rcev_Total_Numbers = 0;
char ph[12] = {'q','a','z','w','s','x','0','1','2','3','4','5'};

int main(int argc, char *argv[])
{
	HANDLE Heart_Signal_Thread;
	unsigned         Thread_ID;
	char   *Send_Data = "0000";
	bool             flag=true;
	int              bytes = 0;
	int                  i = 0;
	if(argc==6)
	{
		if(strlen(argv[3])<13)
		{
			if(strlen(argv[4])<10)
			{
				if(strlen(argv[5])<12)
				{
					memset(pid,0,sizeof(pid));
					memcpy(pid,argv[5],strlen(argv[5]));
				}
				else
				{
					flag=false;
					printf("产品ID越界\n");
				}
				if(flag)
				{
					memset(pwd,0,sizeof(pwd));
					memcpy(pwd,argv[4],strlen(argv[4]));
				}
			}
			else
			{
				flag=false;
				printf("DUT密码越界\n");
			}
			if(flag)
			{
				memset(ph,0,sizeof(ph));
				memcpy(ph,argv[3],strlen(argv[3]));
			}
		}
		else
		{
			flag=false;
			printf("DUT手机号越界\n");
		}
		if(flag)
		{
			memset(str_ip,0,sizeof(str_ip));
			memset(str_port,0,sizeof(str_port));
			memcpy(str_ip,argv[1],strlen(argv[1]));
			memcpy(str_port,argv[2],strlen(argv[2]));
		}
		
	}
	else if(argc==4)
	{
		if(strlen(argv[1])<13)
		{
			if(strlen(argv[2])<10)
			{
				if(strlen(argv[3])<12)
				{
					memset(pid,0,sizeof(pid));
					memcpy(pid,argv[3],strlen(argv[3]));
				}
				else
				{
					flag=false;
					printf("产品ID越界\n");
				}
				if(flag)
				{
					memset(pwd,0,sizeof(pwd));
					memcpy(pwd,argv[2],strlen(argv[2]));
				}
			}
			else
			{
				flag=false;
				printf("DUT密码越界\n");
			}
			if(flag)
			{
				memset(ph,0,sizeof(ph));
				memcpy(ph,argv[1],strlen(argv[1]));
			}
		}
		else
		{
			flag=false;
			printf("DUT手机号越界\n");
		}
	}
	else if(argc==3)
	{
		memset(str_ip,0,sizeof(str_ip));
		memset(str_port,0,sizeof(str_port));
		memcpy(str_ip,argv[1],strlen(argv[1]));
		memcpy(str_port,argv[2],strlen(argv[2]));
	}
	else
	{
		Read_Configure_Info();
	}
	Print_Log();
	TCP_S=SocketConnect(str_ip,str_port);
	Connect_Packet = NewBuffer();
	Connect_Packet = PacketConnect(ph,sizeof(ph),pwd,sizeof(pwd),pid,sizeof(pid));
	//Connect_Packet=PacketConnect(ph,strlen(ph),pwd,sizeof(pwd),pid,sizeof(pid));
	//Login_Data=(char *)Connect_Packet->_data;
	printf("登录信息为:");
	fprintf(fp,"登录信息为:");
	for (i = 0; i < Connect_Packet->_len; i++)
	{
		printf("%c", Connect_Packet->_data[i]);
		fprintf(fp, "%c", Connect_Packet->_data[i]);
	}
	//printf("\nData_Len:%d\n",Connect_Packet->_len);
	printf("\n");
	fprintf(fp,"\n");
	bytes=send(TCP_S,(char *)Connect_Packet->_data,(int)Connect_Packet->_len,0);
	Print_Log_Time();
	printf("发送%d字节登录报文\n",bytes);
	fprintf(fp,"发送%d字节登录报文\n",bytes);
	fclose(fp);
	DeleteBuffer(&Connect_Packet);
	Heart_Signal_Thread = (HANDLE)_beginthreadex(NULL, 0, &SendHeartSignalThreadFunc, NULL, 0, &Thread_ID);
	WaitForSingleObject(Heart_Signal_Thread, INFINITE);
	shutdown(TCP_S, SD_BOTH);
	closesocket(TCP_S);
	WSACleanup();
	return(0);
}
