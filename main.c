#include "sys/socket.h"
#include "netinet/in.h"
#include <netdb.h>



#include "string.h"
#include "stdio.h"
#include "malloc.h"

#define Assert(x) do {if(!(x)) *(int*)0 = 0;} while(0);

#define DEFAULT_ADDRESS 0x7f000002U

#define DEFAULT_PORT 27015U
#define DEFAULT_PORT_STR "27015"

typedef struct IPv4Option{
    unsigned char OptionNumber : 5;
    unsigned char OptionClass : 2;
    unsigned char Copied : 1;
    unsigned char OptionLength;
} IPv4Option;

typedef struct ipv4_header{
    unsigned char ECN : 2;
    unsigned char DSCP : 6;
    unsigned char InternetHeaderLength : 4;
    unsigned char Version : 4;
    unsigned short TotalLength;
    unsigned short Identification;
    unsigned char FragmentOffsetL;
    unsigned char FragmentOffsetH : 5;
    unsigned char MF : 1;
    unsigned char DF : 1;
    unsigned char R  : 1;
    unsigned char Protocol;
    unsigned char TimeToLive;
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
    
    union {
        unsigned char Flags;
        struct {
            unsigned char FIN : 1;
            unsigned char SYN : 1;
            unsigned char RST : 1;
            unsigned char PSH : 1;
            unsigned char ACK : 1;
            unsigned char URG : 1;
            unsigned char ECE : 1;
            unsigned char CWR : 1;
        };
    };
    unsigned char Reserved : 3;
    unsigned char AccurateECN : 1;
    unsigned char DataOffset : 4;
    unsigned short WindowSize;
    unsigned short Checksum;
    unsigned short UrgentPointer;
    char Optional[40];
}tcp_header;


typedef struct tcp_packet{
    ipv4_header Ipv4Header;
    tcp_header TCPHeader;
    pseudo_tcp_header PseudoHeader;
    unsigned char *Data;
    int DataSize;
} tcp_packet;


static inline unsigned int ByteSwapU32(unsigned int In){
    return ((In & 0xff) << 24) | ((In & 0xff00) << 8) | ((In & 0xff0000) >> 8) | ((In & 0xff000000) >>24);
}


static inline unsigned short ByteSwapU16(unsigned short In){
    return ((In & 0xff) << 8) | ((In & 0xff00) >> 8);
}

static inline unsigned short GetFragmentOffset(ipv4_header Header){
    return ((unsigned short)Header.FragmentOffsetH) << 8 | (unsigned short)Header.FragmentOffsetL;
}




static int VerfiyIPv4Checksum(ipv4_header *Header){
    //Algorithm taken from Wikipedia: https://en.wikipedia.org/wiki/Internet_checksum#Algorithm
    
    int sum = 0;
    unsigned short *Value = (unsigned short*)Header;
    int Count = Header->InternetHeaderLength * 4;
    while(Count > 1){
        sum += *Value++;
        Count -= 2;
    }
    
    if(Count > 0){
        sum += (unsigned char)*Value;
    }
    
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    return (~sum & 0xffff) == 0;
    
}

static int VerfiyTCPChecksum(tcp_header *Header,
                              pseudo_tcp_header *PseudoHeader //already converted to Little Endian
                              )
{
    
    //Algorithm taken from Wikipedia: https://en.wikipedia.org/wiki/Internet_checksum#Algorithm
    int sum = 0;
    unsigned short *Value = (unsigned short*) PseudoHeader;
    int i = sizeof(*PseudoHeader);
    Assert(i % 2 == 0);
    while(i > 0){
        sum += *Value++;
        i-=2;
    }
    
    unsigned short PseudoHeaderChecksum = sum;
    Value = (unsigned short*) Header;
    int Count = 20;
    while(Count > 0){
        
        sum +=  (*Value++);
        Count -= 2;
    }
    Count = Header->DataOffset * 4;
    while(Count > 1){

        sum += ByteSwapU16(*Value++);
        Count -= 2;
    }
    if(Count > 0){
        sum += (unsigned char)*Value;
    }
    
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    // Checksum Offloading may only calculate the checksum over the Pseudo Header
    return (sum & 0xffff) == 0 || (PseudoHeaderChecksum == Header->Checksum);
    
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
    Result.Checksum = (unsigned short)Buffer[16] << 8 | (unsigned short)Buffer[17];
    Result.UrgentPointer = Buffer[18] | Buffer [19];
    
    int OptionsSize = Result.DataOffset * 4 - 20;
    if(OptionsSize > 0){
        for(int i = 0; i < OptionsSize; i += 2){
            Result.Optional[i / 2] = *(unsigned short *)(Buffer + 20 + i);
        }
    }

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
    Result.FragmentOffsetH = ((unsigned char)Buffer[6] & 0x1f);
    Result.FragmentOffsetL = (unsigned char)Buffer[7];
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

static unsigned short ComputeTCPIPv4Checksum(ipv4_header IPv4Header)
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
    
    if(Count > 0){
        Sum+= *Value++ << 8;
        
    }
    while(Sum >> 16){
        Sum = (Sum & 0xffff) + (Sum>>16);
    }
    return (~Sum)& 0xffff;
    
}

static unsigned short ComputeTCPChecksum(pseudo_tcp_header *PseudoHeader, 
                                         tcp_header *TCPHeader, 
                                         char *TCPData, 
                                         int TCPDataSize)
{
    
    Assert(TCPHeader->Checksum == 0);
    unsigned int Sum = 0;
    unsigned short *Value = (unsigned short*)PseudoHeader;
    int Count = sizeof(*PseudoHeader);
    Assert(Count % 2 == 0);
    while(Count > 0){
        Sum += *Value++;
        Count-=2;
    }
    Value = (unsigned short*)TCPHeader;
    Count = TCPHeader->DataOffset * 4;
    Assert(Count % 2 == 0);
    while(Count > 0){
        Sum += *Value++;
        Count-=2;
    }
    Value = (unsigned short*)TCPData;
    Count = TCPDataSize;
    while(Count > 1){
        Sum += ByteSwapU16(*Value++);
        Count-=2;
    }
    if(Count > 0){
        Sum+=*Value++ << 8;
        
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
    Buffer[6] |= (unsigned char)(Header.FragmentOffsetH & 0x1f);
    Buffer[7] = (unsigned char)(Header.FragmentOffsetL);
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
    Buffer[12] = Header.DataOffset << 4 | Header.Reserved << 1 | Header.AccurateECN;
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


static tcp_packet ProcessTCPIPPacket(unsigned char* Buffer, int BufferSize){
    tcp_packet Result = {0};
    Result.Ipv4Header = CopyIPv4Header(Buffer, BufferSize);
    Assert(Result.Ipv4Header.Version == 4);
    Assert(Result.Ipv4Header.Protocol == 6);
    int TCPHeaderOffset = Result.Ipv4Header.InternetHeaderLength * 4;
    Result.TCPHeader = CopyTCPHeader(Buffer + TCPHeaderOffset, BufferSize - TCPHeaderOffset);
    int TCPDataOffset = TCPHeaderOffset + Result.TCPHeader.DataOffset * 4;
    int TCPDataSize = Result.Ipv4Header.TotalLength - TCPDataOffset;
    if(TCPDataSize > 0){
        Result.Data = malloc(TCPDataSize);
        Assert(Result.Data);
        memcpy(Result.Data, Buffer + TCPDataOffset, TCPDataSize);
        Result.DataSize = TCPDataSize;
    }
    Result.PseudoHeader.DestAddress = Result.Ipv4Header.DestAddress;
    Result.PseudoHeader.SrcAddress = Result.Ipv4Header.SrcAddress;
    Result.PseudoHeader.Protocol = 6;
    Result.PseudoHeader.TCPLength = Result.Ipv4Header.TotalLength - TCPHeaderOffset;
    return Result;

}

#include "errno.h"
typedef enum tcp_state{
    LISTEN,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT1,
    FIN_WAIT2,
    TIME_WAIT,
    CLOSE_WAIT,
    CLOSED,

    TCP_STATE_COUNT
}tcp_state;

static int HandshakeSYN(int sock, tcp_packet *TCPPacket, unsigned int *SeqNumber, unsigned int *Identification){
    tcp_header SynAckTCPHeader = {};
    SynAckTCPHeader.SrcPort = DEFAULT_PORT;
    SynAckTCPHeader.DestPort = TCPPacket->TCPHeader.SrcPort;

    SynAckTCPHeader.SequenceNumber = *SeqNumber;
    (*SeqNumber)++;
    SynAckTCPHeader.AckNumber = TCPPacket->TCPHeader.SequenceNumber + 1;
    SynAckTCPHeader.DataOffset = 5;
    SynAckTCPHeader.ACK = 1;
    SynAckTCPHeader.SYN = 1;
    SynAckTCPHeader.WindowSize = 512;


    ipv4_header SynAckIPv4Header = {};
    SynAckIPv4Header.Version = 4;
    SynAckIPv4Header.InternetHeaderLength = 5;
    SynAckIPv4Header.TotalLength = SynAckIPv4Header.InternetHeaderLength * 4
        + SynAckTCPHeader.DataOffset * 4;
    SynAckIPv4Header.Identification = (*Identification)++;
    SynAckIPv4Header.DF = 1;
    SynAckIPv4Header.TimeToLive = 64;
    SynAckIPv4Header.Protocol = 6;
    SynAckIPv4Header.SrcAddress = TCPPacket->Ipv4Header.DestAddress;
    SynAckIPv4Header.DestAddress = TCPPacket->Ipv4Header.SrcAddress;


    pseudo_tcp_header SynAckPseudoHeader = {};
    SynAckPseudoHeader.SrcAddress = SynAckIPv4Header.SrcAddress;
    SynAckPseudoHeader.DestAddress = SynAckIPv4Header.DestAddress;
    SynAckPseudoHeader.Protocol = SynAckIPv4Header.Protocol;
    SynAckPseudoHeader.TCPLength = SynAckTCPHeader.DataOffset * 4;
    SynAckTCPHeader.Checksum = ComputeTCPChecksum(&SynAckPseudoHeader, &SynAckTCPHeader, NULL, 0);
    SynAckIPv4Header.Checksum = ComputeTCPIPv4Checksum(SynAckIPv4Header);

    int PacketLength = SynAckIPv4Header.TotalLength;
    unsigned char *Packet = malloc(PacketLength);
    Assert(Packet);
    int Offset = 0;
    Offset += IPv4HeaderToNetBuffer(SynAckIPv4Header, Packet, 512);
    Offset += TCPHeaderToNetBuffer(SynAckTCPHeader, Packet + Offset, 512);
    struct sockaddr_in DestAddress = {0};
    DestAddress.sin_family = AF_INET;
    DestAddress.sin_addr.s_addr = ByteSwapU32(SynAckIPv4Header.DestAddress);
    int iResult = sendto(sock, (char *)Packet, PacketLength, 0, (struct sockaddr *)&DestAddress, sizeof(DestAddress));
    free(Packet);
    if(iResult == -1){
        perror("sendto");
        return 0;
    }
    return 1;
}

static int HTTPHello(int sock, tcp_packet *TCPPacket, unsigned int *SeqNumber, unsigned int *Identification){
    char Payload[] = "HTTP/1.1 200 OK\r\n"
        //"Connection: close\r\n"
        "Content-Length: 18\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hello from Server!";
    int PayloadSize = sizeof(Payload) - 1;

    tcp_packet HTTPResponse = {0};
    HTTPResponse.Data = Payload;
    HTTPResponse.DataSize = PayloadSize;

    HTTPResponse.Ipv4Header.Version = 4;
    HTTPResponse.Ipv4Header.InternetHeaderLength = 5;
    HTTPResponse.Ipv4Header.Identification = (*Identification)++;
    HTTPResponse.Ipv4Header.DF = 1;
    HTTPResponse.Ipv4Header.TimeToLive = 64;
    HTTPResponse.Ipv4Header.Protocol = 6;
    HTTPResponse.Ipv4Header.SrcAddress = DEFAULT_ADDRESS;
    HTTPResponse.Ipv4Header.DestAddress = TCPPacket->Ipv4Header.SrcAddress;

    HTTPResponse.TCPHeader.SrcPort = DEFAULT_PORT;
    HTTPResponse.TCPHeader.DestPort = TCPPacket->TCPHeader.SrcPort;
    HTTPResponse.TCPHeader.AckNumber = TCPPacket->TCPHeader.SequenceNumber + 1;
    HTTPResponse.TCPHeader.SequenceNumber = *SeqNumber;
    HTTPResponse.TCPHeader.DataOffset = 5;
    HTTPResponse.TCPHeader.ACK = 1;
    HTTPResponse.TCPHeader.WindowSize = 512;
    *SeqNumber += HTTPResponse.DataSize;

    HTTPResponse.PseudoHeader.SrcAddress = TCPPacket->Ipv4Header.SrcAddress;
    HTTPResponse.PseudoHeader.DestAddress = TCPPacket->Ipv4Header.DestAddress;
    HTTPResponse.PseudoHeader.Protocol = 6;
    HTTPResponse.PseudoHeader.TCPLength = HTTPResponse.TCPHeader.DataOffset * 4 + HTTPResponse.DataSize;

    HTTPResponse.Ipv4Header.TotalLength = HTTPResponse.Ipv4Header.InternetHeaderLength * 4 + HTTPResponse.PseudoHeader.TCPLength;

    HTTPResponse.TCPHeader.Checksum = ComputeTCPChecksum(&HTTPResponse.PseudoHeader, &HTTPResponse.TCPHeader, HTTPResponse.Data, HTTPResponse.DataSize);
    HTTPResponse.Ipv4Header.Checksum = ComputeTCPIPv4Checksum(HTTPResponse.Ipv4Header);

    int PacketLength = HTTPResponse.Ipv4Header.TotalLength;
    unsigned char *Packet = malloc(PacketLength);
    Assert(Packet);

    int Offset = 0;
    Offset += IPv4HeaderToNetBuffer(HTTPResponse.Ipv4Header, Packet, 512);
    Offset += TCPHeaderToNetBuffer(HTTPResponse.TCPHeader, Packet + Offset, 512);
    memcpy(Packet + Offset, HTTPResponse.Data, HTTPResponse.DataSize);

    struct sockaddr_in DestAddress = {0};
    DestAddress.sin_family = AF_INET;
    DestAddress.sin_addr.s_addr = ByteSwapU32(HTTPResponse.Ipv4Header.DestAddress);

    int iResult = sendto(sock, (char *)Packet, PacketLength, 0, (struct sockaddr *)&DestAddress, sizeof(DestAddress));
    free(Packet);
    if(iResult == -1){
        perror("sendto");
        return 0;
    }
    return 1;
}
static int TerminateACK(int sock, tcp_packet *TCPPacket, unsigned int *SeqNumber, unsigned int *Identification){
    tcp_packet ACKClosePacket = {0};

    ACKClosePacket.Ipv4Header.Version = 4;
    ACKClosePacket.Ipv4Header.InternetHeaderLength = 5;
    ACKClosePacket.Ipv4Header.Identification = (*Identification)++;
    ACKClosePacket.Ipv4Header.DF = 1;
    ACKClosePacket.Ipv4Header.TimeToLive = 64;
    ACKClosePacket.Ipv4Header.Protocol = 6;
    ACKClosePacket.Ipv4Header.SrcAddress = DEFAULT_ADDRESS;
    ACKClosePacket.Ipv4Header.DestAddress = TCPPacket->Ipv4Header.SrcAddress;

    ACKClosePacket.TCPHeader.SrcPort = DEFAULT_PORT;
    ACKClosePacket.TCPHeader.DestPort = TCPPacket->TCPHeader.SrcPort;
    ACKClosePacket.TCPHeader.AckNumber = TCPPacket->TCPHeader.SequenceNumber + 1;
    ACKClosePacket.TCPHeader.SequenceNumber = *SeqNumber;
    ACKClosePacket.TCPHeader.DataOffset = 5;
    ACKClosePacket.TCPHeader.ACK = 1;
    ACKClosePacket.TCPHeader.WindowSize = 512;
    *SeqNumber += ACKClosePacket.DataSize;

    ACKClosePacket.PseudoHeader.SrcAddress = ACKClosePacket.Ipv4Header.SrcAddress;
    ACKClosePacket.PseudoHeader.DestAddress = ACKClosePacket.Ipv4Header.DestAddress;
    ACKClosePacket.PseudoHeader.Protocol = 6;
    ACKClosePacket.PseudoHeader.TCPLength = ACKClosePacket.TCPHeader.DataOffset * 4 + ACKClosePacket.DataSize;

    ACKClosePacket.Ipv4Header.TotalLength = ACKClosePacket.Ipv4Header.InternetHeaderLength * 4 + ACKClosePacket.PseudoHeader.TCPLength;

    ACKClosePacket.TCPHeader.Checksum = ComputeTCPChecksum(&ACKClosePacket.PseudoHeader, &ACKClosePacket.TCPHeader, ACKClosePacket.Data, ACKClosePacket.DataSize);
    ACKClosePacket.Ipv4Header.Checksum = ComputeTCPIPv4Checksum(ACKClosePacket.Ipv4Header);

    int PacketLength = ACKClosePacket.Ipv4Header.TotalLength;
    unsigned char *Packet = malloc(PacketLength);
    Assert(Packet);

    int Offset = 0;
    Offset += IPv4HeaderToNetBuffer(ACKClosePacket.Ipv4Header, Packet, 512);
    Offset += TCPHeaderToNetBuffer(ACKClosePacket.TCPHeader, Packet + Offset, 512);
    memcpy(Packet + Offset, ACKClosePacket.Data, ACKClosePacket.DataSize);
    struct sockaddr_in DestAddress = {0};
    DestAddress.sin_family = AF_INET;
    DestAddress.sin_addr.s_addr = ByteSwapU32(ACKClosePacket.Ipv4Header.DestAddress);

    int iResult = sendto(sock, (char *)Packet, PacketLength, 0, (struct sockaddr *)&DestAddress, sizeof(DestAddress));
    free(Packet);
    if(iResult == -1){
        perror("sendto");
        return 0;
    }

    return 1;
}

static int RejectMessage(int sock, tcp_packet *TCPPacket){
    tcp_header RSTTCPHeader = {};
    RSTTCPHeader.SrcPort = DEFAULT_PORT;
    RSTTCPHeader.DestPort = TCPPacket->TCPHeader.SrcPort;

    RSTTCPHeader.SequenceNumber = 0;
    RSTTCPHeader.AckNumber = 0;
    RSTTCPHeader.DataOffset = 5;
    RSTTCPHeader.ACK = 1;
    RSTTCPHeader.RST = 1;
    RSTTCPHeader.WindowSize = 512;


    ipv4_header RSTIPv4Header = {};
    RSTIPv4Header.Version = 4;
    RSTIPv4Header.InternetHeaderLength = 5;
    RSTIPv4Header.TotalLength = RSTIPv4Header.InternetHeaderLength * 4
        + RSTTCPHeader.DataOffset * 4;
    RSTIPv4Header.Identification = 0;
    RSTIPv4Header.DF = 1;
    RSTIPv4Header.TimeToLive = 64;
    RSTIPv4Header.Protocol = 6;
    RSTIPv4Header.SrcAddress = TCPPacket->Ipv4Header.DestAddress;
    RSTIPv4Header.DestAddress = TCPPacket->Ipv4Header.SrcAddress;


    pseudo_tcp_header SynAckPseudoHeader = {};
    SynAckPseudoHeader.SrcAddress = RSTIPv4Header.SrcAddress;
    SynAckPseudoHeader.DestAddress = RSTIPv4Header.DestAddress;
    SynAckPseudoHeader.Protocol = RSTIPv4Header.Protocol;
    SynAckPseudoHeader.TCPLength = RSTTCPHeader.DataOffset * 4;
    RSTTCPHeader.Checksum = ComputeTCPChecksum(&SynAckPseudoHeader, &RSTTCPHeader, NULL, 0);
    RSTIPv4Header.Checksum = ComputeTCPIPv4Checksum(RSTIPv4Header);

    int PacketLength = RSTIPv4Header.TotalLength;
    unsigned char *Packet = malloc(PacketLength);
    Assert(Packet);
    int Offset = 0;
    Offset += IPv4HeaderToNetBuffer(RSTIPv4Header, Packet, 512);
    Offset += TCPHeaderToNetBuffer(RSTTCPHeader, Packet + Offset, 512);
    struct sockaddr_in DestAddress = {0};
    DestAddress.sin_family = AF_INET;
    DestAddress.sin_addr.s_addr = ByteSwapU32(RSTIPv4Header.DestAddress);
    int iResult = sendto(sock, (char *)Packet, PacketLength, 0, (struct sockaddr *)&DestAddress, sizeof(DestAddress));
    free(Packet);
    if(iResult == -1){
        perror("sendto");
        return 0;
    }
    return 1;
}

int main(){
    int iResult;

    int RawSockIPv4 = -1;
    RawSockIPv4 = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    int TestSocket = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    
    if (RawSockIPv4 == -1) {
        
        char * Error = strerror(errno);
        printf("Error: %s\n",Error);
        
        perror("socket");
        return 1;
    }
    
    struct sockaddr_in SockAddr = {0};
    SockAddr.sin_family = AF_INET;
    SockAddr.sin_addr = (struct in_addr){ByteSwapU32(DEFAULT_ADDRESS)};
    
    iResult = bind(RawSockIPv4, (struct sockaddr*)&SockAddr, sizeof(SockAddr));
    if(iResult == -1){
        perror("bind");
        return 1;
    }
    int SockProt = 0;
    int SockLen = sizeof(SockProt);
    iResult = getsockopt(RawSockIPv4,SOL_SOCKET,SO_PROTOCOL,(char*)&SockProt,&SockLen );
    
    int Enable = 1;
    iResult = setsockopt(RawSockIPv4,IPPROTO_IP,IP_HDRINCL,&Enable, sizeof(Enable));
    
 
    unsigned char Buffer[512] = {0};
    tcp_packet TCPPacket = {0};

    int State = LISTEN;
    unsigned int ConnectionAddress = 0;
    unsigned int ConnectionPort = 0;
    int SeqNumber = 0;
    int Identification = 0x1234;
    while(1){
        iResult = recv(RawSockIPv4, (char*)Buffer, 512, 0);
        if(iResult == -1){
            perror("recvfrom");
            return 1;
        }
        
        TCPPacket = ProcessTCPIPPacket(Buffer, 512);
        Assert(TCPPacket.Ipv4Header.Protocol = 6);

        int ValidIPv4 = VerfiyIPv4Checksum(&TCPPacket.Ipv4Header);
        int ValidTCP = VerfiyTCPChecksum(&TCPPacket.TCPHeader, &TCPPacket.PseudoHeader);
        if(TCPPacket.TCPHeader.DestPort != DEFAULT_PORT | !ValidIPv4 | !ValidTCP){
            free(TCPPacket.Data);
            continue;
        }
        switch(State){
            case LISTEN:{
                Assert(ConnectionAddress == 0 && ConnectionPort == 0);
                if(TCPPacket.TCPHeader.SYN){
                    ConnectionAddress = TCPPacket.Ipv4Header.SrcAddress;
                    ConnectionPort = TCPPacket.TCPHeader.SrcPort;
                    
                    HandshakeSYN(RawSockIPv4, &TCPPacket, &SeqNumber, &Identification);
                    State = SYN_SENT;
                }

            }break;
            case SYN_SENT:{
                if(TCPPacket.TCPHeader.SrcPort == ConnectionPort){
                    if(TCPPacket.Ipv4Header.SrcAddress == ConnectionAddress){
                        if(TCPPacket.TCPHeader.ACK = 1){
                            State = ESTABLISHED;
                        }
                    }
                    else{
                        RejectMessage(RawSockIPv4, &TCPPacket);
                    }
                }
            }break;
            case ESTABLISHED:{
                if(TCPPacket.TCPHeader.SrcPort == ConnectionPort){
                    if(TCPPacket.Ipv4Header.SrcAddress == ConnectionAddress){
                        if(TCPPacket.TCPHeader.FIN == 1 && TCPPacket.TCPHeader.ACK == 1){
                            TerminateACK(RawSockIPv4, &TCPPacket, &SeqNumber, &Identification);
                            printf("Connection Closed\n");
                            ConnectionAddress = 0;
                            ConnectionPort = 0;
                            State = LISTEN;
                        } 
                        else if(TCPPacket.TCPHeader.RST == 1){
                            ConnectionAddress = 0;
                            ConnectionPort = 0;
                            State = LISTEN;
                        }
                        else{
                            if(TCPPacket.DataSize > 0){
                                printf("Data: %s\n", TCPPacket.Data);
                                HTTPHello(RawSockIPv4,&TCPPacket, &SeqNumber, &Identification);
                            }
                        }
                    }
                }
                else{
                    RejectMessage(RawSockIPv4, &TCPPacket);
                }
            }break;
            

        }
    }
   
    
    
    
    
    
}