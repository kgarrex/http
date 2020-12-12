/*
 * RFC 1035 https://www.ietf.org/rfc/rfc1035.txt
 * RFC 4343 https://www.ietf.org/html/rfc4343
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
//#include "core.h"

#pragma comment(lib, "ws2_32.lib")

#define GOOGLE_PRIMARY_DNS_IPV4   "8.8.8.8"
#define GOOGLE_SECONARY_DNS_IPV4  "8.8.4.4"
#define GOOGLE_PRIMARY_DNS_IPV6   "2001:4860:4860::8888"
#define GOOGLE_SECONDARY_DNS_IPV6 "2001:4860:4860::8844"

#define VERISIGN_PRIMARY_DNS "64.6.64.6"
#define VERISIGN_SECONDARY_DNS "64.6.65.6"
#define OPENDNS_PRIMARY_DNS "208.67.222.222"
#define OPENDNS_SECONDARY_DNS "208.67.220.220"
#define FREEDNS_PRIMARY_DNS "37.235.1.174"
#define FREEDNS_SECONDARY_DNS "37.235.163.53"
#define NEUSTAR_PRIMARY_DNS "156.154.70.1"
#define NEUSTAR_SECONDARY_DNS "156.154.71.1"
#define DNS_PORT "53"

#define DNS_QR_QUERY    0
#define DNS_QR_RESPONSE 1

#define DNS_OPCODE_QUERY  0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2
#define DNS_OPCODE_       3
#define DNS_OPCODE_NOTIFY 4
#define DNS_OPCODE_UPDATE 5

#define DNS_RCODE_SUCCESS 0
#define DNS_RCODE_FORMAT_ERROR 1
#define DNS_RCODE_SERVER_FAILURE 2
#define DNS_RCODE_NAME_ERROR 3
#define DNS_RCODE_NOT_IMPL 4
#define DNS_RCODE_REFUSED 5
#define DNS_RCODE_YXDOMAIN 6
#define DNS_RCODE_YX_RR_SET 7
#define DNS_RCODE_NX_RR_SET 8
#define DNS_RCODE_NOT_AUTH 9
#define DNS_RCODE_NOT_ZONE 10


/* Root Servers
 * CNAME              IPv4           IPV6                 Manager
 * a.root-servers.net 198.41.0.4     2001:503:ba3e::2:30  Verisign, Inc.
 * b.root-servers.net 199.9.14.201   2001:500:200::b      University of Souther California (ISI)
 * c.root-servers.net 192.33.4.12    2001:500:2::c        Cogent Communications
 * d.root-servers.net 199.7.91.13    2001:500:2d::d       University of Maryland
 * e.root-servers.net 192.203.230.10 2001:500:a8::e       NASA (Ames Research Center)
 * f.root-servers.net 192.5.5.241    2001:500:2f::f       Internet Systems Consortium, Inc.
 * g.root-servers.net 192.112.36.4   2001:500:12::d0d     US Department of Defens (NIC)
 * h.root-servers.net 198.97.190.53  2001:500:1::53       US Army (Research Lab)
 * i.root-servers.net 192.36.148.17  2001:7fe::53         Netnod
 * j.root-servers.net 192.58.128.30  2001:503:c27::2:30   Verisign, Inc.
 * k.root-servers.net 193.0.14.129   2001:7fd::1          RIPE NCC
 * l.root-servers.net 199.7.83.42    2001:500:9f::42      ICANN
 * m.root-servers.net 202.12.27.33   2001:dc3::35         WIDE Project
*/

/* DNS Servers
 * Google                  8.8.8.8        2001:4860:4860::8888
 *                         8.8.4.4        2001:4860:4860::8844
 * resolver1.opendns.com   208.67.222.222 2620:0:ccc::2               OpenDNS - no filtering
 * resolver2.opendns.com   208.67.220.220 2620:119:35::35             OpenDNS
 * resolver3.opendns.com   208.67.222.220 2620:119:53::53             OpenDNS
 * resolver4.opendns.com   208.67.220.222 2620:0:ccd::2               OpenDNS - no filtering
 * resolver1-fs.opendns.com 208.67.222.123                            OpenDNS - Family Shield
 * resolver2-fs.opendns.com 208.67.220.123                            OpenDNS - Family Shield
 *                          199.85.126.10                             Norton ConnectSafe - Policy A
 *                          199.85.127.10                             Norton ConnectSafe - Policy A
 *                          199.85.126.20                             Norton ConnectSafe - Policy B
 *                          199.85.127.20                             Norton ConnectSafe - Policy B
 *                          199.85.126.30                             Norton ConnectSafe - Policy C
 *                          199.85.127.30                             Norton ConnectSafe - Policy C
 * resolver1.dns.watch      84.200.69.80  2001:1608:10:25::1c04:b12f  DNS Watch
 * resolver2.dns.watch      84.200.70.40  2001:1608:10:25::9249:d69b  DNS Watch
 *                          8.26.56.26                                Comodo Secure DNS
 *                          8.20.247.20                               Comodo Secure DNS
 *                          64.6.64.6     2620:74:1b::1:1             Verisign
 *                          64.6.65.6     2620:74:1c::2:2             Verisign
 * ns1.any.dns.opennic.glue 185.121.177.177  2a05:dfc7:5::53          Fusl
 * ns3.any.dns.opennic.glue 169.239.202.202  2a05:dfc75353:53         Fusl
 * ns7.any.dns.opennic.glue                  2a0d:2144::              dfroe
 *
*/

#define A_ROOT_SERVER_IPV4    0x040029C6
#define GOOGLE_RESOLVER1_IPV4 0x08080808
#define GOOGLE_RESOLVER2_IPV4 0x04040808 //0x08080404
#define GOOGLE_RESOLVER1_IPV6 {0x0120, 0x6048, 0x6048, 0, 0, 0, 0, 0x8888}
#define GOOGLE_RESOLVER2_IPV6 {0x0120, 0x6048, 0x6048, 0, 0, 0, 0, 0x4488}

/* FLAGS */
#define DNS_QR 0x0100 //Response
#define DNS_IQUERY 0x0200 //IQuery
#define DNS_STATUS 0x0600 //Status
#define DNS_NOTIFY 0x0800 //Notify
#define DNS_UPDATE 0x0A00 //Update
#define DNS_AA 0x2000 //Authoritative Answer
#define DNS_TC 0x4000 //Truncated
#define DNS_RD 0x8000 //Recursion Desired

#define DNS_RA 0x0001 //Recursion Available
#define DNS_AD 0x0004 //Authentic Data
#define DNS_CD 0x0008 //Checking Disabled

#define DNS_RCODE_FE 0x0001 //Format Error
#define DNS_RCODE_SF 0x0002 //Server Failure
#define DNS_RCODE_NE 0x0003 //Name Error
#define DNS_RCODE_NI 0x0004 //Not Implemented
#define DNS_RCODE_R  0x0005 //Refused

/*
 RD       :  1, //recursive desired (recursive resolution) (query)
 TC       :  1, //truncated?
 AA       :  1, //authoritative answer?
 OPCODE   :  4,
 QR       :  1, //question or response

 RCODE    :  4, //response code. zero for questions
 CD       :  1, //checking disabled
 AD       :  1, //authentic data
 Z        :  1, //reserved. set to zero
 RA       :  1, //recursion available (response)
 */

    /*
    dh->QR = DNS_QR_QUERY;
    dh->OPCODE = DNS_OPCODE_QUERY;
    dh->AA = 0;
    dh->TC = 0;
    dh->RD = 0;

    dh->RA = 0;
    dh->AD = 0;
    dh->CD = 0;
    dh->Z  = 0;
    dh->RCODE = 0;
    */

struct dns_name{
char length : 8; //length of label
char label[1]; //variable length label
};

struct dns_question{
//unsigned QNAME    : 16;
struct dns_name QNAME[1]; //null terminated list of dns_name
unsigned QTYPE    : 16;
unsigned QCLASS   : 16;
};

enum {
DNS_TYPE_A  = 0x0100,   // a host address
DNS_TYPE_NS = 0x0200,   // an authoritative name server
DNS_TYPE_MD = 0x0300,        // a mail destination
DNS_TYPE_MF,            // a mail forwarder
DNS_TYPE_CNAME = 0x0500,     // a canonical name for an alias
DNS_TYPE_SOA = 0x0600, //start of zone authority
DNS_TYPE_MB,
DNS_TYPE_MG,
DNS_TYPE_MR,
DNS_TYPE_NULL,
DNS_TYPE_WKS,
DNS_TYPE_PTR  = 0x0C00, //reverse dns lookup
DNS_TYPE_HINFO,   // host information
DNS_TYPE_MINFO,   // mailbox or mail list info
DNS_TYPE_MX,      // mail exchange
DNS_TYPE_TXT,      // text strings
DNS_TYPE_AAAA = 0x1C00, //ipv6 address record
DNS_TYPE_LOC  = 0x1D00, //location record
DNS_TYPE_OPENPGPKEY = 0x3D00, //OpenPGP public key record
};

#define DNS_QTYPE_AXFR  0xFC
#define DNS_QTYPE_MAILB 0xFD
#define DNS_QTYPE_MAILA 0xFE
#define DNS_QTYPE_ALL  0xFF

#define DNS_CLASS_IN 0x0100
#define DNS_CLASS_CS 0x0200
#define DNS_CLASS_CH 0x0300
#define DNS_CLASS_HS 0x0400

/*
struct dns_answer{
unsigned NAME     : 16;
unsigned TYPE     : 16; //type of RDATA
unsigned CLASS    : 16; //class; always 1 for internet
unsigned TTL      : 32; //number of seconds results can be cached (time to live)
unsigned RDLENGTH : 16; //length in bytes of RDATA
unsigned RDATA    : 32;
};
*/

struct dns_answer{
const char *name;
short type;
short class;
unsigned int ttl;
unsigned short rdlength;
};

struct dns_packet{
unsigned short
 id       : 16, //id used to track queries
 flags    : 16, //flags
 qdcount  : 16, //number of questions
 ancount  : 16, //number of answers
 nscount  : 16, //number of authority records
 arcount  : 16; //number of additional records
unsigned char data[500];
};
typedef struct dns_packet *DNS_PACKET;


struct dns_record {
unsigned expire;
void *val;
unsigned short len;
unsigned short type;
struct dns_record *next;
};


struct dns_object{
struct dns_packet *packet;
unsigned short packet_size;
char *pdata;
unsigned qdcount;
SOCKET socket;
unsigned short qlen;
unsigned short id;
struct dns_record *records;
void* (*alloc)(unsigned);
};
typedef struct dns_object *DNS_OBJECT;


#define DNSERR_LABEL_TOO_LARGE 0x01
#define DNSERR_TYPE_SIZE_WRONG 0x02

struct dns_object *dns_init(SOCKET socket)
{
struct dns_object *obj;

    obj = malloc(sizeof(struct dns_object));
    assert(obj);

    obj->packet = malloc(sizeof(struct dns_packet));
    assert(obj->packet);
    memset(obj->packet, 0, 12);
    obj->packet_size = sizeof(struct dns_packet);

    obj->pdata = obj->packet->data;
    obj->qlen  = 0;

    obj->socket = socket;
    obj->id = 1;
    
    obj->qdcount = 0;

    obj->alloc = malloc;
    obj->records = 0;

    return obj;
}

unsigned add_question(struct dns_object *obj,
unsigned short type, const char *name, unsigned len)
{
unsigned char n = 0;
char *pdata = obj->pdata;


    /* PARSE THE NAME AND TOKENIZE THE LABELS */
    while(*name){
        if(*name++ != '.') { n++; continue; } 
        *pdata++ = n;
	//printf("%.*s\n", n, name - (n+1));
        memcpy(pdata, name - (n+1), n);
	pdata += n;
	n = 0;
    }
    *pdata++ = n;
    //printf("%.*s\n", n, name - n);
    memcpy(pdata, name - n, n); 
    pdata += n;
    *pdata++ = '\0';

    /* ADD THE TYPE AND CLASS */
    *((short*)pdata) = type; pdata += 2;
    *((short*)pdata) = DNS_CLASS_IN; pdata += 2;

    /* LENGTH OF QUESTION AND INCREMENT QUESTION COUNT */
    obj->qlen += pdata - obj->pdata;
    obj->pdata = pdata;
    obj->qdcount++;

    return 1;
}

unsigned send_packet(struct dns_object *obj, SOCKADDR *saTo)
{
    int size;
    unsigned rslt;

    /* SET THE PACKET ID */
    obj->packet->id = ENDIAN16(obj->id);
    obj->id++;

    /* SET FLAGS */
    obj->packet->flags |= DNS_RD;

    /* SET THE QUESTION COUNT IN THE HEADER */
    obj->packet->qdcount = ENDIAN16(obj->qdcount);

    size = sizeof(SOCKADDR_IN);
    rslt = sendto(obj->socket,
           (const char*)obj->packet, obj->pdata - (char*)obj->packet, 0, saTo, size); 
    if(SOCKET_ERROR == rslt){
        printf("Error %d: sendto\n", WSAGetLastError());
        return 0;
    }

    obj->pdata = obj->packet->data;
    return 1;
}

int get_name_length(struct dns_object *obj, const char *name)
{
int len = 0;
    while(*name){
        if(*name > 63) return DNSERR_LABEL_TOO_LARGE;
        if((*name & 0xc0) == 0xc0){ //compression used
            name = (char*)obj->packet + (ENDIAN16(*((short*)name)) & 0x3fff); //compression offset
            //printf("offset: %u\n", n);
	}
	else{
            len += *name + 1;
            name += *name + 1;
	}
    }
    return --len; //remove last '.'
}

int store_name(struct dns_object *obj, const char *name, char *buf)
{
int n = 0;
int rslt = 0;
const char *tmp = name;
    while(*name){
        if(*name > 63) return DNSERR_LABEL_TOO_LARGE;
        if((*name & 0xc0) == 0xc0){ //compression used
            n = ENDIAN16(*((short*)name)) & 0x3fff; //compression offset
            name = (char*)obj->packet + n;
	    rslt = 2;
	}
	else{
            memcpy(buf, name+1, *name); 
            buf  += *name;
	    name += *name + 1;
            *buf = '.'; buf++;
	}
    }
    name++;
    *(buf-1) = '\0';

    if(rslt) return rslt;
    return name - tmp;
}

int handle_error(unsigned error)
{
    switch(error){
    case DNS_RCODE_FE:
        printf("Error: Format Error\n");
        break;
    case DNS_RCODE_SF: 
        printf("Error: There was a problem with the name server\n");
        break;
    }
   
    return 0;
}

unsigned process_resource_record(struct dns_object *obj, struct dns_record **precord)
{
short type;
short length;
//char *pdata;
int n = 0;
char buf[128];
unsigned ip;
struct dns_record *record = 0;

    record = *precord;

    if(obj->records){
        record->next = obj->alloc(sizeof(struct dns_record));
        assert(record->next);
        record = record->next;
    }
    else{
        record = obj->alloc(sizeof(struct dns_record)); 
        obj->records = record;
        assert(record);
    }

    n = get_name_length(obj, obj->pdata);
    printf("name: %u\n", n);

    n = store_name(obj, obj->pdata, buf);
    obj->pdata += n;
    printf("%s\n", buf); 

    //get type
    type = *((short*)obj->pdata);
    record->type = type;
    printf("type %u\n", ENDIAN16(type));
    obj->pdata += 2;

    //get class
    obj->pdata += 2;

    //get ttl
    record->expire = time(0) + ENDIAN32( *((unsigned *)obj->pdata) );
    obj->pdata += 4;

    //get rdlength 
    length = ENDIAN16( *((short*)obj->pdata) );
    obj->pdata += 2;
    printf("rdlength: %u\n", length);

    //get rdata
    switch(type){
    case DNS_TYPE_A:
        if(length != 4); //error
        ip = ENDIAN32( *((int*)obj->pdata) );
        record->val = (void*)ip;
        record->len = 4;
        printf("%u.%u.%u.%u\n", (ip >> 24) & 0x000000FF, (ip >> 16) & 0x000000FF,
        (ip >> 8)  & 0x000000FF, ip & 0x000000FF);
        break;
             
    case DNS_TYPE_CNAME:
        n = get_name_length(obj, obj->pdata);
        printf("name: %u\n", n);

        record->val = obj->alloc(n+1);
        assert(record->val);
        record->len = n;
        n = store_name(obj, obj->pdata, record->val);
        printf("%.*s\n", record->len, (char*)record->val);
        //record->val = obj->alloc(length);
        break;

    case DNS_TYPE_NS:
        break;

    case DNS_TYPE_AAAA:
        if(length != 16); //error
        record->val = obj->alloc(16);
        memcpy(record->val, obj->pdata, 16);
        record->len = 16;
        break;

    case DNS_TYPE_SOA:
        n = get_name_length(obj, obj->pdata);
        printf("name: %u\n", n);

        record->val = obj->alloc(n+1);
        assert(record->val);
        record->len = n;
        n = store_name(obj, obj->pdata, record->val);
        printf("%.*s\n", record->len, (char*)record->val);
        break;
    }
    obj->pdata += length;
    printf("------------------------------\n");

    *precord = record;
 
    return 0;
}

int recv_packet(struct dns_object *obj, SOCKADDR *saFrom)
{
unsigned rslt, error, fromlen, i, ip;
char *pdata;

    fromlen = sizeof(SOCKADDR_IN);
    rslt = recvfrom(obj->socket, (char *)obj->packet,
           obj->packet_size, 0, (SOCKADDR*)&saFrom, &fromlen); 
    if(SOCKET_ERROR == rslt){
        printf("Error %d: recvfrom\n", WSAGetLastError()); 
        return 1;
    }

    printf("response recieved\n");

    printf("flags 0x%x\n", ENDIAN16(obj->packet->flags) );
    printf("qd count 0x%x\n", ENDIAN16(obj->packet->qdcount) );
    printf("an count ox%x\n", ENDIAN16(obj->packet->ancount) );
    printf("ns count ox%x\n", ENDIAN16(obj->packet->nscount) );
    printf("ar count ox%x\n", ENDIAN16(obj->packet->arcount) );


    error = ENDIAN16(obj->packet->flags) & 0x0f;
    if(error) handle_error(error);

    pdata = obj->pdata;

int n = 0;
char buf[128];
struct dns_record *record = 0;
    for(i = ENDIAN16(obj->packet->qdcount); i; i--)
    {
        n = get_name_length(obj, pdata);   

	n = store_name(obj, pdata, buf);
	pdata += n;

	//get type
	pdata += 2;

	//get class
        pdata += 2;
	printf("----------------------------------\n");
    }

    obj->pdata = pdata;
    for(i = ENDIAN16(obj->packet->ancount); i; i--)
    {
        process_resource_record(obj, &record);
    }

    for(i = ENDIAN16(obj->packet->nscount); i; i--)
    {
        process_resource_record(obj, &record);
    }

    for(i = ENDIAN16(obj->packet->arcount); i; i--)
    {
        process_resource_record(obj, &record);
    }
    return 1;
}

enum _uri_schemes {
JSZLURI_HTTP,
JSZLURI_HTTPS,
JSZLURI_FTP,
JSZLURI_MAILTO,
JSZLURI_FILE,
JSZLURI_DNS,
JSZLURI_GIT,
JSZLURI_RTSP,
JSZLURI_RTSPS,
JSZLURI_RTSPU,
JSZLURI_SKYPE,
JSZLURI_SMTP,
JSZLURI_POP,
JSZLURI_SMS,
JSZLURI_SSH,
JSZLURI_DNTP,
JSZLURI_MONGODB,
JSZLURI_IRC,
JSZLURI_GEO,
JSZLURI_IM,
JSZLURI_LDAP,
JSZLURI_SMB,
JSZLURI_SFTP,
JSZLURI_TELNET,
JSZLURI_TEL,
JSZLURI_UDP,
JSZLURI_SVN,
MAX_URI
};

struct hash {
    unsigned long hashval;
    unsigned int length; 
};

struct hash uri_hashes[] = {
    {1234, 4}
};

struct hash_descriptor {
    unsigned int idx;
    char *string;
};

unsigned long djb2(char *str, unsigned long len, unsigned long *retlen)
{
    unsigned long hash = 5381;

    if(!len){
        if(retlen) *retlen = strlen(str);
        while(*str) hash = ((hash << 5) + hash) + *str++;
    }
    else{
        for(int i = 0; i<len; i++) hash = ((hash << 5) + hash) + str[i]; 
    }
    return hash; 
}

char *array[] = {
    "http",
    "https",
    "ftp",
    "mailto",
    "file",
    "dns",
    "git",
    "rtsp",
    "rtsps",
    "skype",
    "smtp",
    "pop",
    "sms",
    "ssh",
    "dntp",
    "mongodb",
    "irc",
    "geo",
    "im",
    "ldap",
    "smb",
    "sftp",
    "telnet",
    "tel",
    "udp",
    "svn",
};


int create_hash_array(char *str_array[], int size)
{
    unsigned long length;
    unsigned long hash;
    char *string;

    printf("struct hash scheme_hashes[] = {\n");
    for(int i = 0; i < size; i++)
    {
        hash = djb2(str_array[i], 0, &length);
	printf("    {%u, %u},\n", hash, length);
    }
    printf("};\n");
    return 0;
}

struct hash scheme_hashes[] = {
    {2090341317, 4},
    {261786840, 5},
    {193492015, 3},
    {221776075, 6},
    {2090257189, 4},
    {193489642, 3},
    {193492745, 3},
    {2090700654, 4},
    {273644961, 5},
    {274513969, 5},
    {2090729001, 4},
    {193502740, 3},
    {193505944, 3},
    {193506131, 3},
    {2090191035, 4},
    {3577282891, 7},
    {193495203, 3},
    {193492608, 3},
    {5863483, 2},
    {2090467014, 4},
    {193505927, 3},
    {2090721378, 4},
    {500577009, 6},
    {193506762, 3},
    {193507822, 3},
    {193506236, 3}
};

typedef unsigned long (*hashfn)(char*, unsigned long, unsigned long*);
typedef int (*uri_handler)(const char*);


int find_scheme(unsigned long hash, unsigned long length)
{
    for(int i = 0; i < (sizeof(scheme_hashes)/sizeof(scheme_hashes[0])); i++)
    {
        if(scheme_hashes[i].hashval == hash && scheme_hashes[i].length == length)
            return i;
    }
    return -1;
}

int http_handler(const char *str)
{
    if(str[0] != ':' || str[1] != '/' || str[2] != '/') return 0; 
    str += 3;

    if(*str == '[') //expecting ip address

    //if(*str == j
    while(*str){
        //if(*str == '/') 
    }
    //while(*str != '.')
}

int dns_handler(const char *str)
{
    return 0;
}

int file_handler(const char *str)
{
    return 0;
}

int git_handler(const char *str)
{
    return 0;
}

int rtsp_handler(const char *str)
{
    return 0;
}

int mailto_handler(const char *str)
{
    return 0;
}

//rfc3966
int tel_handler(const char *str)
{
    return 0;
}

uri_handler handler_array[] = {
    http_handler
   ,http_handler
   ,0
   ,mailto_handler
};




int validate_uri(char *uri, hashfn hasher)
{
    unsigned long hash;
    unsigned long length;
    char *str = uri;
    int i = 0;
    uri_handler handler;

    //process the scheme
    while(*str != ':')
    {
        if(i > 10) return 0; 
        str++;
	i++;
    }
    length = str - uri;
    hash = hasher(uri, length, 0); 
    i = find_scheme(hash, length);
    //printf("%.*s %u %u\n", length, uri, hash, length);
    printf("index %u\n", i);
    
    if(!handler_array[i](str)) return 0;
    return 1;
}


int main(int argc, char **argv)
{
WSADATA wsadata;
SOCKET socket;
SOCKADDR_IN saTo   = {0};
SOCKADDR_IN saFrom = {0};
int rslt = 0;
unsigned int fromlen;
unsigned int query_size;
char *name;
struct dns_object *dnsobj;

    saTo.sin_family = AF_INET;
    saTo.sin_port   = 0x3500;
    saTo.sin_addr.S_un.S_addr = GOOGLE_RESOLVER1_IPV4; //GOOGLE_RESOLVER2_IPV4;

    WSAStartup(MAKEWORD(2,2), &wsadata);

    socket = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, 0);

    dnsobj = dns_init(socket);

    saFrom.sin_family = AF_INET;
    rslt = bind(socket, (SOCKADDR*)&saFrom, sizeof(saFrom));
    if(SOCKET_ERROR == rslt){
        printf("Error %d: bind\n", WSAGetLastError());
        return 1;	
    }
    printf("socket bound...\n");
    

    add_question(dnsobj, DNS_TYPE_A, "www.google.com", 0);
    add_question(dnsobj, DNS_TYPE_CNAME, "www.google.com", 0);

    if( send_packet(dnsobj, (SOCKADDR*)&saTo) )
        printf("msg sent...\n");


    recv_packet(dnsobj, (SOCKADDR*)&saFrom);
    //read_answer(&dns_answer);

    //create_hash_array(array, sizeof(array)/sizeof(array[0]));

    if(!validate_uri("http://google.com", djb2)){
        printf("bad url\n"); 
    }
 
    return 1;
}
