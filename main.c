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

typedef struct pseudo_tcp_header{
    unsigned int SrcAddress;
    unsigned int DestAddress;
    unsigned char Protocol;
    unsigned char zero;
    unsigned short TCPLength;
    
} pseudo_tcp_header;

typedef struct tcp_header{
    unsigned short SrcPort;
    unsigned short DestPort;
    unsigned int SequenceNumber;
    unsigned int AckNumber;
    unsigned char DataOffset : 4;
    unsigned char Reserved : 3;
    unsigned char AccurateECN : 1;
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
    Result.SequenceNumber = ((unsigned int) Buffer[4]) << 24 
        | ((unsigned int)Buffer[5])  << 16
        | ((unsigned int) Buffer[6]) <<  8 
        | ((unsigned int)Buffer[7]);
    Result.AckNumber = ((unsigned int) Buffer[8]) << 24 
        | ((unsigned int)Buffer[9])  << 16
        | ((unsigned int) Buffer[10]) <<  8 
        | ((unsigned int)Buffer[11]);
    Result.DataOffset = (Buffer[12]>>4) & 0xf;
    Result.Reserved = Buffer[12] & 0x7;
    Result.AccurateECN = (Buffer[12]>>3) & 0x1;
    Result.CWR = Buffer[13] >> 7 & 0x1;
    Result.ECE = Buffer[13] >> 6 & 0x1;
    Result.URG = Buffer[13] >> 5 & 0x1;
    Result.ACK = Buffer[13] >> 4 & 0x1;
    Result.PSH = Buffer[13] >> 3 & 0x1;
    Result.RST = Buffer[13] >> 2 & 0x1;
    Result.SYN = Buffer[13] >> 1 & 0x1;
    Result.FIN = Buffer[13] >> 0 & 0x1;
    Result.WindowSize = Buffer[14] | Buffer[15];
    Result.Checksum = Buffer[16] | Buffer[17];
    Result.UrgentPointer = Buffer[18] | Buffer [19];
    return Result;
}

static inline unsigned int ByteSwapU32(unsigned int In){
    return ((In & 0xff) << 24) | ((In & 0xff00) << 8) | ((In & 0xff0000) >> 8) | ((In & 0xff000000) >>24);
}


static inline unsigned short ByteSwapU16(unsigned short In){
    return ((In & 0xff) << 8) | ((In & 0xff00) >> 8);
}




static int VerfiyIPv4Checksum(unsigned char *Buffer, int BufferSize, int Count){
    //Algorithm taken from Wikipedia: https://en.wikipedia.org/wiki/Internet_checksum#Algorithm
    
    Assert(BufferSize >= Count);
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

static int VerfiyTCPChecksum(unsigned char *TCPSegment, 
                             int SegmentSize,
                             pseudo_tcp_header PseudoHeader //already converted to Little Endian
                             )
{
    
    //Algorithm taken from Wikipedia: https://en.wikipedia.org/wiki/Internet_checksum#Algorithm
    int sum = 0;
    unsigned short *Value = (unsigned short*) &PseudoHeader;
    int i = sizeof(PseudoHeader);
    Assert(i % 2 == 0);
    while(i > 0){
        sum += *Value++;
        i-=2;
    }
    
    Value = (unsigned short*) TCPSegment;
    int Count =  SegmentSize;
    while(Count > 1){
        //The Segment is still in Big Endian. Convert before adding.
        sum +=  ByteSwapU16(*Value++);
        Count -= 2;
    }
    
    if(Count > 0){
        sum += (unsigned char)*TCPSegment;
    }
    
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    return (sum & 0xffff) == 0;
    
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



#include "stdlib.h"

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
    
    
    
    ipv4_header  Header;
    pseudo_tcp_header PseudoHeader = {};
    tcp_header TCPHeader = {};
    char *Data;
    char Buffer[512] = {};
    
    while(1){
        iResult = recvfrom(RawSockIPv4, Buffer, 512, 0,NULL,0 );
        if(iResult ==SOCKET_ERROR){
            printf("recvfrom error: %ld\n", WSAGetLastError());
            return 1;
        }
        
        Header = CopyIPv4Header(Buffer, sizeof(Buffer));
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
        
        
        memset(&PseudoHeader,0,sizeof(PseudoHeader));
        PseudoHeader.SrcAddress = (Header.SrcAddress);
        PseudoHeader.DestAddress =(Header.DestAddress);
        PseudoHeader.Protocol = Header.Protocol;
        PseudoHeader.TCPLength = (Header.TotalLength - HeaderLengthInBytes);
        
        
        int DataSize = PseudoHeader.TCPLength;
        Data = malloc(DataSize);
        Assert(Data);
        memcpy(Data,Buffer + HeaderLengthInBytes,DataSize);
        
        memset(&TCPHeader,0,sizeof(TCPHeader));
        TCPHeader = CopyTCPHeader(Data,DataSize); 
        if(TCPHeader.DestPort == 27015){
            break;
        }
        free(Data);
        Data = 0;
        
        
    }
    
    printf("Total Length: %u\n", Header.TotalLength);
    printf("Source Address: %hhd.%hhd.%hhd.%hhd\n", Header.SrcIP[3],Header.SrcIP[2],Header.SrcIP[1],Header.SrcIP[0]);
    printf("Destination Address: %hhd.%hhd.%hhd.%hhd\n", Header.DestIP[3],Header.DestIP[2],Header.DestIP[1],Header.DestIP[0]);
    
    int tcp_verfied = VerfiyTCPChecksum(Data, PseudoHeader.TCPLength, PseudoHeader);
    if(tcp_verfied){
        printf("Src Port: %hu\n", TCPHeader.SrcPort);
        printf("Dest Port: %hu\n", TCPHeader.DestPort);
        
        
    }
    
    
    
    
    
    
}