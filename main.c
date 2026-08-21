#include "sys/socket.h"
#include "netinet/in.h"
#include <netdb.h>



#include "string.h"
#include "stdio.h"
#include "malloc.h"

#define Assert(x) do {if(!(x)) *(int*)0 = 0;} while(0);


#define DEFAULT_PORT "27015"

typedef struct IPv4Option{
    unsigned char OptionNumber : 5;
    unsigned char OptionClass : 2;
    unsigned char Copied : 1;
    unsigned char OptionLength;
} IPv4Option;

typedef struct ipv4_header{
    unsigned char Version : 4;
    unsigned char InternetHeaderLength : 4;
    unsigned char DSCP : 6;
    unsigned char ECN : 2;
    unsigned short TotalLength;
    unsigned short Identification;
    unsigned short R  : 1;
    unsigned short DF : 1;
    unsigned short MF : 1;
    
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
    union{
        //sizeof(IPv4Option) == 2 => 20 Options fit into 40Bytes
        struct IPv4Option Options[20]; 
        unsigned char Optional[40];
    };
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


static int VerfiyIPv4Checksum2(unsigned char *Buffer, int BufferSize, int Count){
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

static int VerfiyTCPChecksum2(unsigned char *TCPSegment, 
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
        sum +=  (*Value++);
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

static tcp_header CopyTCPHeader(unsigned char *Buffer, int BufferSize){
    tcp_header Result = {0};
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


static ipv4_header CopyIPv4Header(unsigned char *Buffer, int BufferSize){
    Assert(BufferSize >= 20);
    ipv4_header Result = {0};
    
    Result.Version = (Buffer[0] >> 4) &0xf;
    Result.InternetHeaderLength = Buffer[0] & 0xf;
    Result.DSCP = (Buffer[1] >> 2) & 0x3f;
    Result.ECN = Buffer[1] & 0x3;
    Result.TotalLength = ((unsigned short) Buffer[2]) << 8 | ((unsigned short)Buffer[3]);
    Result.Identification = ((unsigned short) Buffer[4]) << 8 | ((unsigned short)Buffer[5]);
    Result.R  = (Buffer[6] >> 5)& 0x1;
    Result.DF = (Buffer[6] >> 6)& 0x1;
    Result.MF = (Buffer[6] >> 7)& 0x1;
    Result.FragmentOffset = (((unsigned short)Buffer[7]) << 5 )
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
    
    int OptionsSize = Result.InternetHeaderLength * 4 - 20;
    Assert(OptionsSize >= 0);
    memcpy(Result.Optional,Buffer + 20, OptionsSize);
    return Result;
    
};

static unsigned short ComputeTCPIPv4Checksum(ipv4_header IPv4Header, 
                                             tcp_header TCPHeader, 
                                             char *TCPData, 
                                             int TCPDataSize)
{
    
    Assert(IPv4Header.Checksum == 0);
    unsigned int Sum = 0;
    unsigned short *Value = (unsigned short*)&IPv4Header;
    int Count = IPv4Header.InternetHeaderLength * 4;
    Assert(Count % 2 == 0);
    while(Count > 0){
        Sum += *Value++;
        Count-=2;
    }
    Value = (unsigned short*)&TCPHeader;
    Count = TCPHeader.DataOffset * 4;
    Assert(Count % 2 == 0);
    while(Count > 0){
        Sum += *Value++;
        Count-=2;
    }
    Value = (unsigned short*)TCPData;
    Count = TCPDataSize;
    while(Count > 1){
        Sum += *Value++;
        Count-=2;
    }
    if(Count > 0){
        Sum+=*(unsigned char*)Value++;
    }
    while(Sum >> 16){
        Sum = (Sum & 0xffff) + (Sum>>16);
    }
    return (~Sum)& 0xffff;
    
}

static unsigned short ComputeTCPChecksum(pseudo_tcp_header PseudoHeader, 
                                         tcp_header TCPHeader, 
                                         char *TCPData, 
                                         int TCPDataSize)
{
    
    Assert(TCPHeader.Checksum == 0);
    unsigned int Sum = 0;
    unsigned short *Value = (unsigned short*)&PseudoHeader;
    int Count = sizeof(PseudoHeader);
    Assert(Count % 2 == 0);
    while(Count > 0){
        Sum += *Value++;
        Count-=2;
    }
    Value = (unsigned short*)&TCPHeader;
    Count = TCPHeader.DataOffset * 4;
    Assert(Count % 2 == 0);
    while(Count > 0){
        Sum += *Value++;
        Count-=2;
    }
    Value = (unsigned short*)TCPData;
    Count = TCPDataSize;
    while(Count > 1){
        Sum += *Value++;
        Count-=2;
    }
    if(Count > 0){
        Sum+=*(unsigned char*)Value++;
    }
    while(Sum >> 16){
        Sum = (Sum & 0xffff) + (Sum>>16);
    }
    return (~Sum)& 0xffff;
    
}


static int IPv4HeaderToNetBuffer(ipv4_header Header,unsigned char *Buffer, int BufferSize){
    Assert(BufferSize >= Header.InternetHeaderLength * 4);
    Assert(Buffer);
    
    Buffer[0] = Header.Version << 4 | Header.InternetHeaderLength;
    Buffer[1] = Header.DSCP << 6 | Header.ECN;
    Buffer[2] = (Header.TotalLength >> 8);
    Buffer[3] = (Header.TotalLength & 0xff);
    Buffer[4] = (Header.Identification >> 8);
    Buffer[5] = (Header.Identification & 0xff);
    Buffer[6] = (unsigned char)Header.R  << 5;
    Buffer[6] |= (unsigned char)Header.DF << 6;
    Buffer[6] |= (unsigned char)Header.MF << 7;
    Buffer[6] |= (unsigned char)(Header.FragmentOffset & 0x1f);
    Buffer[7] = (unsigned char)((Header.FragmentOffset) >> 5);
    Buffer[8] = Header.TimeToLive;
    Buffer[9] = Header.Protocol;
    Buffer[10] = (unsigned char)(Header.Checksum >> 8);
    Buffer[11] = (unsigned char)(Header.Checksum & 0xff);
    Buffer[12] = (unsigned char)((Header.SrcAddress >> 24)&0xff);
    Buffer[13] = (unsigned char)((Header.SrcAddress >> 16)&0xff);
    Buffer[14] = (unsigned char)((Header.SrcAddress >> 8)&0xff);
    Buffer[15] = (unsigned char)(Header.SrcAddress & 0xff);
    Buffer[16] = (unsigned char)((Header.DestAddress >> 24)&0xff);
    Buffer[17] = (unsigned char)((Header.DestAddress >> 16)&0xff);
    Buffer[18] = (unsigned char)((Header.DestAddress >> 8)&0xff);
    Buffer[19] = (unsigned char)(Header.DestAddress & 0xff);
    
    int OptionSize = Header.InternetHeaderLength * 4 - 20;
    Assert(OptionSize >= 0);
    for(int i = 0; i < 20; i++){
        //Variable Sized Options not supported
        Assert(Header.Options[i].OptionLength <=4);
    }
    memcpy(Buffer + 20, Header.Optional, OptionSize);
    
    
    return 20 + OptionSize;
}


static int TCPHeaderToNetBuffer(tcp_header Header, unsigned char* Buffer, int BufferSize){
    Assert(BufferSize >= Header.DataOffset * 4);
    Assert(Buffer);
    Buffer[0] = (unsigned char)(Header.SrcPort>>8);
    Buffer[1] = (unsigned char)(Header.SrcPort & 0xff);
    Buffer[2] = (unsigned char)(Header.DestPort >> 8);
    Buffer[3] = (unsigned char)(Header.DestPort & 0xff);
    Buffer[4] = (unsigned char)((Header.SequenceNumber >> 24)&0xff);
    Buffer[5] = (unsigned char)((Header.SequenceNumber >> 16)&0xff);
    Buffer[6] = (unsigned char)((Header.SequenceNumber >> 8)&0xff);
    Buffer[7] = (unsigned char) (Header.SequenceNumber & 0xff);
    Buffer[8] = (unsigned char)((Header.AckNumber >> 24) & 0xff);
    Buffer[9] = (unsigned char)((Header.AckNumber >> 16) & 0xff);
    Buffer[10] = (unsigned char)((Header.AckNumber >> 8) & 0xff);
    Buffer[11] = (unsigned char)((Header.AckNumber >> 0) & 0xff);
    Buffer[12] = Header.DataOffset << 4| Header.Reserved << 1| Header.AccurateECN;
    Buffer[13] = Header.CWR << 7;
    Buffer[13] |= Header.ECE << 6;
    Buffer[13] |= Header.URG << 5;
    Buffer[13] |= Header.ACK << 4;
    Buffer[13] |= Header.PSH << 3;
    Buffer[13] |= Header.RST << 2;
    Buffer[13] |= Header.SYN << 1;
    Buffer[13] |= Header.FIN << 0;
    Buffer[14] = (unsigned char)(Header.WindowSize >> 8);
    Buffer[15] = (unsigned char)(Header.WindowSize & 0xff);
    Buffer[16] = (unsigned char)(Header.Checksum >> 8);
    Buffer[17] = (unsigned char)(Header.Checksum & 0xff);
    Buffer[18] = (unsigned char)(Header.UrgentPointer >> 8);
    Buffer[19] = (unsigned char)(Header.UrgentPointer & 0xff);
    
    return 20;
}



/*
int TCPHeaderLength = TCPHeader.DataOffset * 4;
    int TCPDataLength = PseudoHeader.TCPLength - TCPHeaderLength;
    
char *TCPData = 0;
    if(TCPDataLength > 0){
        malloc(TCPDataLength);
        Assert(TCPData);
        memcpy(TCPData,TCPSegment + TCPHeaderLength, TCPDataLength);
    }
    */

int main(){
    
    
    
    int iResult;
    
    int RawSockIPv4 = -1;
    RawSockIPv4= socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    
    if (RawSockIPv4 == -1) {
        perror("socket");
        return 1;
    }
    
    /*
    struct addrinfo *SocketAddressInfo = 0;
    iResult = getaddrinfo("127.0.0.1",NULL,NULL,(struct addrinfo**) &SocketAddressInfo);
    */
    struct sockaddr_in SockAddr = {0};
    SockAddr.sin_family = AF_INET;
    SockAddr.sin_addr = (struct in_addr){0x0100007fU};
    /*
    iResult = bind(RawSockIPv4, (struct sockaddr*)&SockAddr, sizeof(SockAddr));
    if(iResult == -1){
        perror("bind");
        return 1;
    }*/
    
    
    
    
    ipv4_header  IPv4Header;
    pseudo_tcp_header PseudoHeader = {0};
    tcp_header TCPHeader = {0};
    unsigned char *TCPSegment;
    unsigned char Buffer[512] = {0};
    
    while(1){
        iResult = recvfrom(RawSockIPv4, (char*)Buffer, 512, 0,NULL, NULL);
        if(iResult == -1){
            perror("recvfrom");
            return 1;
        }
        
        IPv4Header = CopyIPv4Header(Buffer, sizeof(Buffer));
        Assert(IPv4Header.Version==4);
        //Length is in 32bit/4bytes => IHL * 4 is length in bytes
        unsigned int HeaderLengthInBytes = (IPv4Header.InternetHeaderLength << 2); 
        if( HeaderLengthInBytes > 20){
            Assert(HeaderLengthInBytes >= 60);
            memcpy(IPv4Header.Optional, Buffer + 20, HeaderLengthInBytes - 20);
        }
        
        
        int Verfied = 0;
        
        if(IPv4Header.Protocol == 0x6){
            Verfied = VerfiyIPv4Checksum(Buffer,512, IPv4Header.InternetHeaderLength << 2);
        }
        printf("Verficiation: %s\n",Verfied ? "Success" : "Failed");
        
        
        memset(&PseudoHeader,0,sizeof(PseudoHeader));
        PseudoHeader.SrcAddress = (IPv4Header.SrcAddress);
        PseudoHeader.DestAddress =(IPv4Header.DestAddress);
        PseudoHeader.Protocol = IPv4Header.Protocol;
        PseudoHeader.TCPLength = (unsigned short)(IPv4Header.TotalLength - HeaderLengthInBytes);
        
        
        int DataSize = PseudoHeader.TCPLength;
        TCPSegment = malloc(DataSize);
        Assert(TCPSegment);
        memcpy(TCPSegment,Buffer + HeaderLengthInBytes,DataSize);
        
        memset(&TCPHeader,0,sizeof(TCPHeader));
        TCPHeader = CopyTCPHeader(TCPSegment,DataSize); 
        if(TCPHeader.DestPort == 27015){
            break;
        }
        free(TCPSegment);
        TCPSegment= 0;
        
        
    }
    
    printf("Total Length: %u\n", IPv4Header.TotalLength);
    printf("Source Address: %hhd.%hhd.%hhd.%hhd\n", IPv4Header.SrcIP[3],IPv4Header.SrcIP[2],IPv4Header.SrcIP[1],IPv4Header.SrcIP[0]);
    printf("Destination Address: %hhd.%hhd.%hhd.%hhd\n", IPv4Header.DestIP[3],IPv4Header.DestIP[2],IPv4Header.DestIP[1],IPv4Header.DestIP[0]);
    
    int tcp_verfied = VerfiyTCPChecksum(TCPSegment, PseudoHeader.TCPLength, PseudoHeader);
    if(tcp_verfied){
        printf("Src Port: %hu\n", TCPHeader.SrcPort);
        printf("Dest Port: %hu\n", TCPHeader.DestPort);
    }
    if(TCPHeader.SYN){
        
        
        tcp_header SynAckTCPHeader = {};
        SynAckTCPHeader.SrcPort = TCPHeader.DestPort;
        SynAckTCPHeader.DestPort = TCPHeader.SrcPort;
        
        SynAckTCPHeader.SequenceNumber = 1234;
        SynAckTCPHeader.AckNumber = TCPHeader.SequenceNumber + 1;
        SynAckTCPHeader.DataOffset = 5;
        SynAckTCPHeader.ACK = 1;
        SynAckTCPHeader.SYN = 1;
        SynAckTCPHeader.WindowSize = 512;
        
        
        ipv4_header SynAckIPv4Header = {};
        SynAckIPv4Header.Version = 4;
        SynAckIPv4Header.InternetHeaderLength = 5;
        SynAckIPv4Header.TotalLength = SynAckIPv4Header.InternetHeaderLength * 4 
            + SynAckTCPHeader.DataOffset * 4; 
        SynAckIPv4Header.Identification = 0x1234;
        SynAckIPv4Header.DF = 1;
        SynAckIPv4Header.TimeToLive = 10;
        SynAckIPv4Header.Protocol = 5;
        SynAckIPv4Header.SrcAddress = IPv4Header.DestAddress;
        SynAckIPv4Header.DestAddress = IPv4Header.SrcAddress;
        
        
        pseudo_tcp_header SynAckPseudoHeader = {};
        SynAckPseudoHeader.SrcAddress = SynAckIPv4Header.SrcAddress;
        SynAckPseudoHeader.DestAddress = SynAckIPv4Header.DestAddress;
        SynAckPseudoHeader.Protocol = SynAckIPv4Header.Protocol;
        SynAckPseudoHeader.TCPLength = SynAckTCPHeader.DataOffset * 4;
        
        
        
        
        SynAckTCPHeader.Checksum = ComputeTCPChecksum(SynAckPseudoHeader,SynAckTCPHeader,NULL,0);
        SynAckIPv4Header.Checksum = ComputeTCPIPv4Checksum(SynAckIPv4Header,SynAckTCPHeader,NULL,0);
        
        int PacketLength = SynAckIPv4Header.TotalLength;
        
        unsigned char *Packet = malloc(PacketLength);
        Assert(Packet);
        int Offset = 0;
        
        Offset += IPv4HeaderToNetBuffer(SynAckIPv4Header,Packet,512);
        Offset += TCPHeaderToNetBuffer(SynAckTCPHeader,Packet+Offset,512);
        
        
        
        
        
        iResult = sendto(RawSockIPv4, (char*)Packet, PacketLength,0, NULL,0);
        if(iResult == -1){
            perror("sendto");
            return 1;
        }
        
        
        
        
        
    }
    
    
    
    
}