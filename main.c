#include <stdio.h>

/*
typedef struct _DNS_CACHE_ENTRY {
	struct _DNS_CACHE_ENTRY *Next;
	PWSTR Name;
	unsigned short Type;
	unsigned short DataLength;
	unsigned long Flags;
} DNSCACHEENTRY, *PDNSCACHEENTRY;

typedef int (__stdcall *DnsGetCacheDataTable)(PDNSCACHEENTRY);
*/


#define URL_MAX_LENGTH 2048
#define URL_MAX_SCHEME_LENGTH 10
#define URL_SCHEME_HASH_TABLE_SIZE 256

int transport_write()
{
	return 0;
}

int transport_read()
{
	return 0;
}

enum url_scheme_enum{
	url_scheme_pop3,
	url_scheme_pop3s,
	url_scheme_smtp,
	url_scheme_ftp,
	url_scheme_http,
	url_scheme_https,
	url_scheme_ssh,
	url_scheme_git,
	url_scheme_svn,
	url_scheme_sftp,
	url_scheme_amazon_s3,
	url_scheme_dns,
	url_scheme_irc,
	url_scheme_smb,
	url_scheme_rtsp,
	url_scheme_odbc,
	url_scheme_tel,
};

typedef struct url_scheme {
	const char *text;
	char length;
	int hash;
	int flags;
	unsigned short default_port;
	int (*callback)(const char *url);
} url_scheme;


void http_cb(const char *url)
{

}


struct url_scheme schemes[] = {
	{"pop",     3, 0, 0, 110, 0},
	{"pop",     3, 0, 0, 995, 0},
	{"mailto",  6, 0, 0, 25, 0},
	{"ftp",     3, 0, 0, 21, 0},
	{"http",    4, 0, 0, 80, http_cb},
	{"https",   5, 0, 0, 443, 0},
	{"ssh",     3, 0, 0, 22, 0},
	{"git",     3, 0, 0, 9418, 0},
	{"svn",     3, 0, 0, 3690, 0},
	{"sftp",    4, 0, 0, 22, 0},
	{"s3",      2, 0, 0, 0, 0},
	{"dns",     3, 0, 0, 53, 0},
	{"irc",     3, 0, 0, 6697, 0},
	{"smb",     3, 0, 0, 445, 0},
	{"rtsp",    4, 0, 0, 554, 0},
	{"odbc",    4, 0, 0, 1433, 0},
	{"tel",     3, 0, 0, 0, 0},
};

struct url_fields {
	int scheme;
	union {
		struct {
			unsigned short port;
			char *path[256];
		} http;

		struct {
			unsigned short port;	
		} dns;

		struct {
			unsigned short port;	
		} ftp;
	};
};

unsigned int key_hash(const char *key, unsigned int length)
{
	unsigned int hash = 5381;

	if(length){
		for(int i = 0; i < length; ++i)
			hash = (hash << 5) + hash + *key++;
	}
	else {
		for(; *key; key++)
			hash = (hash << 5) + hash + *key;
	}
	return hash;
}

const char *lookup_scheme_by_index(unsigned int index, unsigned int *plength)
{

}

struct url_scheme *
lookup_scheme_by_name(const char *name, unsigned int length)
{
	unsigned int hash;
	hash = key_hash(name, length);

	printf("%u\n", hash); 

	return 0;
}

void url_read(struct url_fields *fields, const char *url)
{
	int length = 0;
	char *head, *tail;

	head = tail = url;

	//read chars up to colon, hash value and perform 
	while(*tail != ':')
	{
		tail++;
	}
	lookup_scheme_by_name(head, tail - head);

	head = ++tail;

}

int url_write(struct url_fields *fields, char *buf)
{
	/*
	struct url_scheme *scheme_ptr;
	char *ptr = buf;
	//fields->scheme

	scheme_ptr = &schemes[fields->scheme];
	memcpy(ptr, scheme_ptr->text, scheme_ptr->length); 

	ptr += scheme_ptr->length;

	*ptr++ = ':';

	if(scheme_ptr->flags & URL_COMPONENT_SLASH)
	{
		*ptr++ = '/';	
		*ptr++ = '/';
	}

	if(!fields->http.port) return 0;
	if(fields->port != scheme_ptr->default_port)
	{
		//write port out	
	}
	*/

	return 0;
	
}

int main(int argc, char *argv[])
{
	struct url_fields fields;
	const char *url = "http://google.com";

	url_read(&fields, url);
	return 1;
}
