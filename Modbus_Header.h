#ifndef __MODBUS_HEADER_H__
#define __MODBUS_HEADER_H__

#define MOSQ_MSB(A)         (uint8)((A & 0xFF00) >> 8)
#define MOSQ_LSB(A)         (uint8)(A & 0x00FF)
#define BUFFER_SIZE         (0x01<<20)
typedef unsigned char   uint8;
typedef char            int8;
typedef unsigned short  uint16;
typedef short           int16;
typedef unsigned int    uint32;
typedef int             int32;
typedef struct Buffer
{
	uint8*  _data;
	uint32  _len;
}Buffer, SendBuffer, RecvBuffer, ModbusPacket,*PModbusRecvPacket;

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

/*
 *内存申请函数
 */
Buffer* NewBuffer(void);

/*
 *释放内存函数
 */
void DeleteBuffer(Buffer** buf);

/*
 *向申请的空间中写入一个字节内容
 */
int32 WriteByte(Buffer* buf, uint8 byte);

/*
 *将bytes指针指向的内容的count字节写入到buf中
 */
int32 WriteBytes(Buffer* buf, const void* bytes, uint32 count);

/*
 *将一个无符号的短整型数据写入到buf中
 */
int32 WriteUint16(Buffer* buf, uint16 val);

/*
 *CRC16校验码生成函数
 */
unsigned int CRC16(unsigned char *puchMsg,unsigned int  usDataLen);

/*
 *连接包生成函数
 */
ModbusPacket *PacketConnect(const char *phone, int phoneLen, const char *pwd, int pwdLen, const char* pid, int pidLen);

/*
 *Ping包生成函数
 */
ModbusPacket *PacketPing(void);

/*
 *时间格式化函数
 */
void Print_Log_Time(void);

/*
 *打开日志文件函数
 */
void Print_Log(void);

/*
 *将字符串端口转换为短整型端口函数
 */
unsigned short StrTOShort(char *str_port);

/*
 *命令回复函数
 */
void Recv_Cmd_Function(char *CMD,int CMD_Len);

/*
 *Socket链接函数
 */
SOCKET SocketConnect(char *ip,char *port);

/*
 *线程函数
 */
unsigned __stdcall SendHeartSignalThreadFunc(void* pArguments);

/*
 *字符串比较函数
 */
bool String_match(char *str_src,char *str_dst);

/*
 *读取配置文件函数
 */
void Read_Configure_Info(void);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* __MODBUS_HEADER_H__ */
