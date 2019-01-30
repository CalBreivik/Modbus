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
 *�ڴ����뺯��
 */
Buffer* NewBuffer(void);

/*
 *�ͷ��ڴ溯��
 */
void DeleteBuffer(Buffer** buf);

/*
 *������Ŀռ���д��һ���ֽ�����
 */
int32 WriteByte(Buffer* buf, uint8 byte);

/*
 *��bytesָ��ָ������ݵ�count�ֽ�д�뵽buf��
 */
int32 WriteBytes(Buffer* buf, const void* bytes, uint32 count);

/*
 *��һ���޷��ŵĶ���������д�뵽buf��
 */
int32 WriteUint16(Buffer* buf, uint16 val);

/*
 *CRC16У�������ɺ���
 */
unsigned int CRC16(unsigned char *puchMsg,unsigned int  usDataLen);

/*
 *���Ӱ����ɺ���
 */
ModbusPacket *PacketConnect(const char *phone, int phoneLen, const char *pwd, int pwdLen, const char* pid, int pidLen);

/*
 *Ping�����ɺ���
 */
ModbusPacket *PacketPing(void);

/*
 *ʱ���ʽ������
 */
void Print_Log_Time(void);

/*
 *����־�ļ�����
 */
void Print_Log(void);

/*
 *���ַ����˿�ת��Ϊ�����Ͷ˿ں���
 */
unsigned short StrTOShort(char *str_port);

/*
 *����ظ�����
 */
void Recv_Cmd_Function(char *CMD,int CMD_Len);

/*
 *Socket���Ӻ���
 */
SOCKET SocketConnect(char *ip,char *port);

/*
 *�̺߳���
 */
unsigned __stdcall SendHeartSignalThreadFunc(void* pArguments);

/*
 *�ַ����ȽϺ���
 */
bool String_match(char *str_src,char *str_dst);

/*
 *��ȡ�����ļ�����
 */
void Read_Configure_Info(void);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* __MODBUS_HEADER_H__ */
