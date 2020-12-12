#include <stdio.h>

/*
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31
	 , !, ", #, $, %, &, 0, (, ), *, +, ', -, ., /,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, :, ;, <, =, >, ?, 63
	@, A, B, C, D, E, F, G, H, I, J, K, L, M, N, O,
	P, Q, R, S, T, U, V, W, X, Y, Z, [, \, ], ^, _, 95
	`, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o,
	p, q, r, s, t, u, v, w, x, y, z, {, |, }, ~, 0, 127
*/

/* HTTP Headers
 *
 * A-IM
 * Accept
 * Accept-Charset
 * Accept-Encoding
 * Accept-Language
 * Accept-Datetime
 * Accept-Patch
 * Access-Control-Request-Method
 * Access-Control-Request-Headers
 * Age
 * Allow
 * Authorization
 * Cache-Control
 * Connection
 * Content-Length
 * Content-MD5     **obsolete**
 * Content-Type
 * Cookie
 * Date
 * Digest
 * Expect
 * Forwarded
 * From
 * Host
 * Keep-Alive
 * Last-Modified
 * Link
 * Location
 * Origin
 * Range
 * Referer
 * Referrer-Policy
 * Server
 * Set-Cookie
 * Transfer-Encoding
 * User-Agent
 * Via
 * WWW-Authenticate
 *
*/

/* HTTP Request Methods
** CONNECT
** DELETE
** GET
** HEAD
** OPTIONS
** PATCH
** POST
** PUT
** TRACE
*/

/* HTTP Status Codes
 * 100 Continue
 * 101 Switching Protocols
 * 102 Processing
 * 103 Early Hints
 * 200 OK
 * 201 Created
 * 202 Accepted
 * 203 Non-Authoritative Information
 * 204 No Content
 * 205 Reset Content
 * 206 Partial Content
 * 207 Multi-Status
 * 208 Already Reported
 * 226 IM Used
 * 300 Multiple Choices
 * 301 Moved Permanently
 * 302 Found
 * 303 See other
 * 304 Not Modified
 * 305 Use Proxy
 * 306 Switch Proxy
 * 307 Temporary Redirect
 * 308 Permanent Redirect
 * 400 Bad Request
 * 401 Unauthorized 
 * 402 Payment Required
 * 403 Forbidden
 * 404 Not Found
 * 405 Method Not allowed
 * 406 Not acceptable
 * 407 Proxy Authentication Required
 * 408 Request Timeout
 * 409 Conflict
 * 410 Gone
 * 411 Length Required
 * 412 Precondition Failed
 * 413 Payload Too Large
 * 414 URI Too Long
 * 415 Unsupported Media Type
 * 416 Range Not Satisfiable
 * 417 Expectation Failed
 * 422 Unprocessed Entity
 * 425 Too Early
 * 426 Upgrade Required
 * 428 Precondition Required
 * 429 Too Many Requests
 * 431 Request Header Fields Too Large
 * 451 Unavailable For Legal Reasons
 * 500 Internal Server Error
 * 501 Not Implemented
 * 502 Bad Gateway
 * 503 Service Unavailable
 * 504 Gateway Timeout
 * 505 HTTP Version Not Supported
 * 506 Variant Also Negotiates
 * 507 Insufficient Storage
 * 508 Loop Detected
 * 511 Network Authentication Required
*/



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

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;


typedef unsigned char bool;
#define true 1
#define false 0


#define isdigit(c) (c>47 && c<58)
#define isalpha(c) ((c>64&&c<91)||(c>96&&c<123))
#define ishexdigit(d) (isdigit(d)||(d>64&&d<71)||(d>96&&d<103))


#define URL_MAX_LENGTH 2048
#define URL_MAX_SCHEME_LENGTH 10
#define URL_SCHEME_HASH_TABLE_SIZE 256


#define PORT_MAX_LENGTH 5
#define IPV4_MAX_LENGTH 15
#define IPV6_MAX_LENGTH


enum url_error {
	url_error_none,
	url_error_bad_port,
	url_error_bad_ipv6,
};

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


typedef struct url_scheme {
	const char *text;
	char length;
	int hash;
	int flags;
	int (*parser)(struct url_fields *, const char *url);
} url_scheme;



/*
** @param plength : A pointer to the length of the string
** 	if the plength is NULL, the string is expected to be
**	a null-terminated string. if *plength is set to zero,
**	the operation will process up to a max limit or it reaches an invalid char.
**	if *plength is non-zero, the procedure will the length provided
*/


int npx_atoi32(unsigned int *plength, const char *str, char base, int *val)
{
	unsigned int c;
	int n = 0;
	int len =0;

	const unsigned char table[] =
	{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	};
	

	if(plength == NULL){
		//null-terminated string
	}
	else if(*plength == 0){
		//unknown length
	}
	else {
		//known length
	}

	switch(base){
	case 10:
		if(len){
			while(len--){
				c = table[*str++];
				if(c > 9) {}//error
				n = ((n<<3) + (n<<1)) + c;

			}
		}
		else {
			while(*str){
				c = table[*str++];
				if(c > 9) {}//error	
				n = ((n<<3) + (n<<1)) + c;

			}
		}
		/*
		for(int i = 0; i < len; ++i)
		{
			n = ((n<<3) + (n<<1)) + (*str - 48);
			++str;
		}
		*/
		break;
	case 16:

		/*
		if(len){
			while(len--){
				c = table[*str++];
				if(c > 15){} //error
				n = (n<<4) + c;
			}
		}
		else {
			while(*str){
				c = table[*str++];
				if(c > 15){} //error	
				n = (n<<4) + c;
			}
		}
		*/

		for(c = *str; len--; c = *++str)
		{
			n = (n<<4) + (c > '9' ? toupper(c) - 7 : c) - '0';
		}
		break;
	default:
		return 0;
	}

	*val = n;

	return 0;
}

#include "ip.c"

#define set_url_component(var)\
	var = head; var##_length = tail - head; head = tail

/*
const char *url_find_path(const char *str)
{
}

int url_http_tokenize(const char *url)
{
}
*/

//url_decode(const char *in, const char *out

#define MAX_HOST_LENGTH 253
#define MAX_HOST_LABEL_LENGTH 63


#define URL_COMPONENT_PATH           0x01
#define URL_COMPONENT_QUERY          0x02
#define URL_COMPONENT_FRAGMENT       0x04
#define URL_COMPONENT_AUTHORITY      0x08
#define URL_COMPONENT_IPV6_LITERAL   0x10
#define URL_COMPONENT_USERINFO       0x20
#define URL_COMPONENT_PORT           0x40

struct url_string {
	const char *ptr;
	unsigned short length;
};

struct url_authority_host {
	char host_type;
	union {
		struct url_string *name;
		npxipv4_t ipv4_address;
		npxipv6_t ipv6_address;	
	};
};

enum url_parser_enum {
	url_parse_error_none,
	url_parser_eof,
	url_parser_continue,
};

typedef struct {
	char scheme;
	unsigned short port;
} npxurl;

struct url_parser {
	unsigned short length;

	//struct url_string userinfo;
	//struct url_authority_host host;
	//unsigned short port;
	
	npxurl *url;

	const char *authority;
	short authority_length;

	const char *userinfo;
	short userinfo_length;

	const char *host;
	short host_length;

	const char *port;
	short port_length;

	const char *path;
	short path_length;

	const char *query;
	short query_length;

	const char *fragment;
	short fragment_length;

	const char **part_ptr;
	short *length_ptr;

	char component;
	int error;
};

#define HANDLE_PART(PART)\
	*(url->length_ptr) = str - *(url->part_ptr);\
	url->PART = str;\
	url->part_ptr = &url->PART;\
	url->length_ptr = &url->PART##_length





int symbol_null(struct url_parser *url, const char *str)
{
	*(url->length_ptr) = str - *(url->part_ptr);
	return url_parser_eof;
}

int symbol_at(struct url_parser *url, const char *str)
{
	if(url->component != URL_COMPONENT_AUTHORITY) return 0;

	url->userinfo = url->authority;
	url->userinfo_length = str - url->userinfo;
	url->port = 0;
	return url_parser_continue;
}

int symbol_colon(struct url_parser *url, const char *str)
{
	if(url->component == URL_COMPONENT_AUTHORITY){
		url->port = str;	
	}
	return url_parser_continue;
}

int symbol_slash(struct url_parser *url, const char *str)
{
	if(url->path) return url_parser_continue;

	url->component = URL_COMPONENT_PATH;
	HANDLE_PART(path);

	return url_parser_continue;
}


int symbol_question(struct url_parser *url, const char *str)
{
	if(url->query) return url_parser_continue;

	url->component = URL_COMPONENT_QUERY;
	HANDLE_PART(query);

	return url_parser_continue;
}

int symbol_hash(struct url_parser *url, const char *str)
{
	if(url->fragment) return url_parser_continue;
	
	url->component = URL_COMPONENT_FRAGMENT;
	HANDLE_PART(fragment);

	return url_parser_continue;
}

int symbol_lbracket(struct url_parser *url, const char *str)
{
	if(url->component == URL_COMPONENT_AUTHORITY){
		url->component = URL_COMPONENT_IPV6_LITERAL;	
	}
	return url_parser_continue;
}

int symbol_rbracket(struct url_parser *url, const char *str)
{
	if(url->component == URL_COMPONENT_IPV6_LITERAL){
		url->component = URL_COMPONENT_AUTHORITY;	
	}
	return url_parser_continue;
}

#define ptrval(t,p) (*((t*)p))

#define MAX_URL_SIZE 2048

int url_parser_split(struct url_parser *url, const char *urlstr, int length)
{

	const unsigned char char_table[] =
	{
	 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //31
	-1, -1, -1,  5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  3,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  2, -1, -1, -1, -1,  4, //63
	 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  6, -1,  7, -1, -1, //95
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //127
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //159
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //191
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //223
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //255
	};

	int (*handler[])(struct url_parser *, const char *) = {
		symbol_null,
		symbol_at,
		symbol_colon,
		symbol_slash,
		symbol_question,
		symbol_hash,
		symbol_lbracket,
		symbol_rbracket
	};

	unsigned register idx;
	char *end;
	const char *tail;
	int result;

	if(ptrval(short, urlstr) != 0x2f2f){
		return 0;
	}
	urlstr += 2;

	tail = urlstr;
	url->authority = urlstr; 
	url->part_ptr = &url->authority;
	url->length_ptr = &url->authority_length;

	url->component = URL_COMPONENT_AUTHORITY;

	if(length){
		if(length > MAX_URL_SIZE) {
			//fatal error
		}
		end = (char*)(urlstr + length);
	}
	else end = (char*)(urlstr + MAX_URL_SIZE);

loop:
	if(tail == end){
		result = handler[0](url, tail);
		goto exit_loop;
	}
	idx = char_table[*tail];
	if(idx > 7) goto next_symbol;
	result = handler[idx](url, tail);
	if(url_parser_continue != result){
		goto exit_loop;
	}

next_symbol:
	++tail;
	goto loop;

exit_loop:

	url->length = tail - urlstr;

	//handle the port
	if(url->port){
		url->port_length =
		(url->authority + url->authority_length) - url->port - 1;
	}

	//handle the host
	url->host = url->authority + url->userinfo_length;
	url->host_length =
	((url->authority + url->authority_length) - url->port_length) - url->host;

	return 1;
}



/*
 * port handler
	int portnum;
		//should stip off leading zeroes here
		if(port_length > 5) {
			//port too long, invalid port
			printf("Error: Port too long\n");
		}
		else if(port_length < 1){
			//set port to 0 for default
		}
		else {

			//convert port to int
			result = npx_atoi32(port_length, url->port+1, 10, &portnum);
			if(result || (portnum > 65536))
			{
				//invalid port	
			}
			printf("Port: %u\n", portnum);
		}

*/


int url_parse_http(struct url_fields *fields, const char *urlstr)
{
	int n;
	int i;
	int len;
	const char *head, *tail;

	//struct url_authority auth;
	struct url_parser url = {0};

	url_parser_split(&url, urlstr, 0);

	printf("Authority: %.*s\n", url.authority_length, url.authority);

	if(url.userinfo)
		printf("UserInfo: %.*s\n", url.userinfo_length, url.userinfo);
	if(url.host)
		printf("Host: %.*s\n", url.host_length, url.host);
	/*
	if(url.port)
		printf("Port: %.*s\n", url.port_length, url.port);
	*/


	if(url.path)
		printf("Path: %.*s\n", url.path_length, url.path);
	if(url.query)
		printf("Query: %.*s\n", url.query_length, url.query);
	if(url.fragment)
		printf("Fragment: %.*s\n", url.fragment_length, url.fragment);


	return 0;



	/*
ip_check:
	if(*tail == '['){
		len = npx_ipv6_string(0, ++tail, host_length);
		if(len){
			tail += len;
			if(*tail++ != ']'){
				return url_error_bad_ipv6;
			}
			goto port_check;
		}
	}
	else {
		len = npx_ipv4_string(0, tail, host_length);
		if(len){
			tail += len;
			goto port_check;
		}
	}
	*/

	return url_error_none;
}

int url_parse_ftp()
{
	return 0;
}

/*
 * pop 110
 * pop 995
 * mailto 25
 * ftp 21
 * http 80
 * https 443
 * ssh 22
 * git 9418
 * svn 3690
 * sftp 22
 * dns 53
 * irc 6697
 * smb 445
 * rtsp 554
 * odbc 1433
*/


struct url_scheme scheme_parser[] = {
	{"pop",     3, 0, 0, 0},
	{"pop",     3, 0, 0, 0},
	{"mailto",  6, 0, 0, 0},
	{"ftp",     3, 0, 0, 0},
	{"http",    4, 0, 0, url_parse_http},
	{"https",   5, 0, 0, 0},
	{"ssh",     3, 0, 0, 0},
	{"git",     3, 0, 0, 0},
	{"svn",     3, 0, 0, 0},
	{"sftp",    4, 0, 0, 0},
	{"s3",      2, 0, 0, 0},
	{"dns",     3, 0, 0, 0},
	{"irc",     3, 0, 0, 0},
	{"smb",     3, 0, 0, 0},
	{"rtsp",    4, 0, 0, 0},
	{"odbc",    4, 0, 0, 0},
	{"tel",     3, 0, 0, 0},
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

const char *lookup_scheme_by_enum(unsigned int index, unsigned int *plength)
{
	
	return 0;
}

struct url_scheme *
lookup_scheme_by_name(const char *name, unsigned int length)
{
	unsigned int hash;
	hash = key_hash(name, length);

	return &scheme_parser[4];
}


/*
 * bufsize : [in] the size of the buffer
 * 	[out] the size of the url string copied to the buffer	
*/

int url_serialize(npxurl *url, char buffer, int *bufsize)
{
	return 0;
}


void url_parse(npxurl *url, const char *urlstr)
{
	int result = 0;
	char *head, *tail;

	struct url_scheme *scheme;

	head = tail = urlstr;

	//read chars up to colon, hash value and perform 
	while(*tail != ':')
	{
		++tail;
	}


	scheme = lookup_scheme_by_name(head, tail - head);

	head = ++tail;

	result = scheme->parser(url, head);
	if(result != url_error_none)
	{
		printf("Error: invalid url\n");	
	}

}

int url_write(struct url *fields, char *buf)
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


enum {
	http_request_get,
	http_request_connect,
	http_request_delete,
	http_request_head,
	http_request_options,
	http_request_patch,
	http_request_post,
	http_request_put,
	http_request_trace,
};

enum {
	http_connection_keep_alive,
	http_connection_close,
};

struct http_header {
	int method;
	char version;

	int date; //the date in unix time (seconds)

	char *content_type;
	int content_length;

	char *allow;
};

struct http_request_header {
	struct http_header header;

	char *host;
	char *path;
	char *user_agent;
	char *authorization;
	char accept_language;

	/* gzip, compress, deflate, br, identity, gzip;q=1.0, *;q=0.5 */
	char accept_encoding;
};

struct http_response_header {
	struct http_header header;

	char *server;
	int last_modified; //unix time
	int age; //num seconds
	char *location; //url to redirect page
};


http_read_request()
{

}


int main(int argc, char *argv[])
{
	npxipv6_t ipv6;
	unsigned int len = 0;
	struct url_fields fields;
	int error;
	
	npxurl url;
	const char *urlstr = "http://ken:garrett@google.com:8080/this/is/a/path?query=param#frament";

	const char *url_list[] = {
		"http://www.example.com/",
		"https://www.example.com/",
		"http://example.com/arm?airplane=boundary&board=bike",
		"https://www.example.com/advice.htm?boat=bait&agreement=battle",
		"https://example.com/bait/boy",
		"http://books.example.org/?bell=bite",
		"http://actor.example.com/airplane",
		"https://www.example.net/art",
		"http://www.example.com/",
		"http://behavior.example.net/arithmetic/baby",
		"http://bath.example.com/",
		"http://example.com/blade.aspx",
		"http://www.example.com/anger.php",
		"http://example.com/brass.html",
		"http://www.example.com/advertisement",
		"http://example.org/bubble.html?berry=bat&baseball=baseball",
		"http://www.example.org/",
		"https://www.example.net/apparel/arch?boy=apparel&branch=authority",
		"https://www.example.net/badge",
		"https://www.example.net/?baseball=apparatus",
		"https://sageprotection.com/ed/19/index.html"
	};

	npx_ipv4_string(0, "194.123.133.135", &len);

	len = 0;
	npx_ipv6_string(&ipv6, "::1", &len);

	printf("%u:%u:%u:%u:%u:%u:%u:%u\n",
		ipv6.hextet[0],
		ipv6.hextet[1],
		ipv6.hextet[2],
		ipv6.hextet[3],
		ipv6.hextet[4],
		ipv6.hextet[5],
		ipv6.hextet[6],
		ipv6.hextet[7]
	);

	len = 0;
	error =
	npx_ipv6_string(&ipv6, "1234:2345:3456:4567:5678:6789:789A:89A::9ABC", &len);

	if(error) printf("Bad IPv6 string");
	else printf("ipv6 length: %u\n", len);

	int val = 0xafba;

	__asm {
		mov eax, val 
		xchg al, ah
		ror al, 4
		mov val, eax
	};

	printf("val: 0x%x\n", val);

	//printf("len: %u\n", len);

	url_parse(&url, urlstr);

	return 1;
}
