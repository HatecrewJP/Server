#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


#include "windows.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include "iphlpapi.h"
#include "stdio.h"

#include "malloc.h"

#define Assert(x) do {if(!(x)) __debugbreak();} while(0);


#pragma comment(lib,"Ws2_32.lib")

#define DEFAULT_PORT "27015"

typedef struct ipv4_header{
    unsigned char Version : 4;
    unsigned char InternetHeaderLength : 4;
    unsigned char DSCP : 6;
    unsigned char ECN : 2;
    unsigned short TotalLength;
    unsigned short Identification;
    unsigned short Flags : 3;
    unsigned short FragmentOffset : 13;
    unsigned char TimeToLive;
    unsigned char Protocol;
    unsigned short Checksum;
    union{
        unsigned int SrcAddress;
        unsigned char SrcIP[4];
    };
    union{
        unsigned int DestAddress;
        unsigned char DestIP[4];
    };
    char Optional[40];
} ipv4_header;


typedef struct tcp_header{
    unsigned short SrcPort;
    unsigned short DestPort;
    unsigned int SequenceNumber;
    unsigned char DataOffset : 4;
    unsigned char Reserved : 4;
    union {
        unsigned char Flags;
        struct {
            unsigned char CWR : 1;
            unsigned char ECE : 1;
            unsigned char URG : 1;
            unsigned char ACK : 1;
            unsigned char PSH : 1;
            unsigned char RST : 1;
            unsigned char SYN : 1;
            unsigned char FIN : 1;
        };
    };
    unsigned short WindowSize;
    unsigned short Checksum;
    unsigned short UrgentPointer;
    char Optional[40];
}tcp_header;

static tcp_header CopyTCPHeader(unsigned char *Buffer, int BufferSize){
    tcp_header Result = {};
    Assert(BufferSize >= 20);
    
    
    Result.SrcPort = (((unsigned short)Buffer[0]) << 8 )| (unsigned short)Buffer[1];
    Result.DestPort = (((unsigned short)Buffer[2]) << 8) | (unsigned short)Buffer[3];
    return Result;
}


static int VerfiyIPv4Checksum(unsigned char *Buffer, int BufferSize, int Count){
    //Algorithm taken from Wikipedia: https://en.wikipedia.org/wiki/Internet_checksum#Algorithm
    
    Assert(BufferSize > Count);
    int sum = 0;
    unsigned short *Value = (unsigned short*) Buffer;
    while(Count > 1){
        sum += *Value++;
        Count -= 2;
    }
    
    if(Count > 0){
        sum += (unsigned char)*Buffer;
    }
    
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    return (~sum & 0xffff) == 0;
    
}


static ipv4_header CopyIPv4Header(unsigned char *Buffer, int BufferSize){
    Assert(BufferSize >= 20);
    ipv4_header Result = {};
    
    Result.Version = (Buffer[0] >> 4) &0xf;
    Result.InternetHeaderLength = Buffer[0] & 0xf;
    Result.DSCP = (Buffer[1] >> 2) & 0x3f;
    Result.ECN = Buffer[1] & 0x3;
    Result.TotalLength = ((unsigned short) Buffer[2]) << 8 | ((unsigned short)Buffer[3]);
    Result.Identification = ((unsigned short) Buffer[4]) << 8 | ((unsigned short)Buffer[5]);
    Result.Flags = (Buffer[6] >> 5)& 0x7;
    Result.FragmentOffset = (((unsigned short)Buffer[7]) << 8 )
        | ((unsigned short)Buffer[6] & 0x1f);
    Result.TimeToLive = Buffer[8];
    Result.Protocol = Buffer[9];
    Result.Checksum = ((unsigned short) Buffer[10]) << 8 | ((unsigned short)Buffer[11]);
    Result.SrcAddress = ((unsigned int) Buffer[12]) << 24 
        | ((unsigned int)Buffer[13])  << 16
        | ((unsigned int) Buffer[14]) <<  8 
        | ((unsigned int)Buffer[15]);
    Result.DestAddress = ((unsigned int) Buffer[16]) << 24 
        | ((unsigned int)Buffer[17])  << 16
        | ((unsigned int) Buffer[18]) <<  8 
        | ((unsigned int)Buffer[19]);
    return Result;
    
};





int main(){
    WSADATA wsaData;
    int iResult;
    iResult = WSAStartup(MAKEWORD(2,2),&wsaData);
    if(iResult){
        printf("WSA startup failed\n");
        return 1;
    }
    
    struct addrinfo *result = NULL;
    struct addrinfo *ptr = NULL;
    struct addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_IP;
    hints.ai_flags = AI_PASSIVE;
    
    iResult = getaddrinfo(NULL,DEFAULT_PORT,&hints,&result);
    if(iResult){
        printf("GetAddrInfo failed %d\n", iResult);
        WSACleanup();
        return 1;
    }
    
    SOCKET RawSockIPv4 = INVALID_SOCKET;
    RawSockIPv4= socket(result->ai_family,result->ai_socktype,result->ai_protocol);
    
    if (RawSockIPv4 == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        WSACleanup();
        freeaddrinfo(result);
        return 1;
    }
    
    iResult = bind(RawSockIPv4, result->ai_addr, (int)result->ai_addrlen);
    if(iResult == SOCKET_ERROR){
        printf("bind failed: %ld\n", WSAGetLastError());
        closesocket(RawSockIPv4);
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
    freeaddrinfo(result);
    
    
    char Buffer[512] = {};
    
    iResult = recvfrom(RawSockIPv4, Buffer, 512, 0,NULL,0 );
    if(iResult ==SOCKET_ERROR){
        printf("recvfrom error: %ld\n", WSAGetLastError());
        return 1;
    }
    
    ipv4_header Header = CopyIPv4Header(Buffer, sizeof(Buffer));
    Assert(Header.Version==4);
    //Length is in 32bit/4bytes => IHL * 4 is length in bytes
    unsigned int HeaderLengthInBytes = (Header.InternetHeaderLength << 2); 
    if( HeaderLengthInBytes > 20){
        Assert(HeaderLengthInBytes >= 60);
        memcpy(Header.Optional, Buffer + 20, HeaderLengthInBytes - 20);
    }
    
    
    int Verfied = 0;
    
    if(Header.Protocol == 0x6){
        Verfied = VerfiyIPv4Checksum(Buffer,512, Header.InternetHeaderLength << 2);
    }
    Assert(Verfied);
    
    
    printf("Total Length: %u\b", Header.TotalLength);
    printf("Source Address: %x\n", Header.SrcAddress);
    printf("Destination Address: %x\n", Header.DestAddress);
    
    int DataSize = Header.TotalLength - HeaderLengthInBytes;
    char *Data = malloc(DataSize);
    Assert(Data);
    memcpy(Data,Buffer + HeaderLengthInBytes,DataSize);
    
    
    tcp_header TCPHeader = CopyTCPHeader(Data,DataSize); 
    
    
    
    
    
    
    
}