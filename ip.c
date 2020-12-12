
typedef union {
	unsigned char octet[4];	
	unsigned int ipv4;
} npxipv4_t;

typedef union{
	unsigned char octet[16];
	unsigned short hextet[8];
	unsigned int quadlet[4];
	//unsigned long long octlet[2];
	
	//Aggregate Global Unicast Address
	struct {
		uint32_t prefix     : 3;
		union {
			uint64_t global_routing_prefix : 45;
			struct {
				uint32_t tla_id : 13;
				uint32_t res    : 8;
				uint32_t nla_id : 24;
			};
		};
		uint32_t sla_id : 16;
		uint64_t intf_id;
	} unicast;

	//Link-Local-Use Address
	struct {
		uint64_t prefix : 10;
		uint64_t reserved : 54;
		uint64_t intfid;
	} link_local;

	//Site-Local-Use Address
	struct {
		int x;
	} site_local;

	struct {
		uint8_t fp;
		uint8_t flags : 4;
		uint8_t scope : 4;
		uint8_t group_id[14];
	} multicast;

} npxipv6_t;

typedef union {
	unsigned char octet[6];
} npxmac_t;

#define MIN_IPV4_LENGTH 7
#define MAX_IPV4_LENGTH 15

#define MAX_IPV6_LENGTH 39
#define MIN_IPV6_LENGTH 3

enum {
	string_success,
	string_too_long,
	string_too_short,
};


const unsigned char atoi_table[] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

#define base10_table(c) (atoi_table[c])
#define base16_table(c) (atoi_table[c])
#define mul10(n) ((n<<3)+(n<<1))
#define mul16(n) (n<<4)


#define PP_NARG(...) PP_NARG_(__VA_ARGS__, PP_RSEQ_N())
#define PP_NARG_(...) PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N(\
	 _1,  _2,  _3,  _4,  _5,  _6,  _7,  _8,  _9, _10,\
	_11, _12, _13, _14, _15, _16, _17, _18, _19, _20,\
	_21, _22, _23, _24, _25, _26, _27, _28, _29, _30,\
	_31, _32, _33, _34, _35, _36, _37, _38, _39, _40,\
	_41, _42, _43, _44, _45, _46, _47, _48, _49, _50,\
	_51, _52, _53, _54, _55, _56, _57, _58, _59, _60,\
	_61, _62, _63, N, ...) N
#define PP_RSEQ_N()\
	63,62,61,60,\
	59,58,57,56,55,54,53,52,51,50,\
	49,48,47,46,45,44,43,42,41,40,\
	39,38,37,36,35,34,33,32,31,30,\
	29,28,27,26,25,24,23,22,21,20,\
	19,18,17,16,15,14,13,12,11,10,\
	 9, 8, 7, 6, 5, 4, 3, 2, 1, 0


/*
 * errcodes:
 * 1 = string too short
 * 2 = invalid char
*/


int npx_ipv4_string(npxipv4_t *ipv4, const char *ip_string, unsigned int *plen)
{
	
	const char *str, *end;
	register i, j;
	char octet;
	int errcode = 0;
	unsigned char digit;


	//assert(ip_string);
	//assert(plen);

	str = ip_string;

	if(*plen){
		if(*plen < 7){
			errcode = 1;
			goto exit;
		}
		end = str + *plen;
	}
	else end = str + 15;


	i = 0;
	goto char_loop;

	next_group:
	//store the previous octet here
	if(++i > 3) goto exit;
	if(*str != '.'){
		errcode = 2;
		goto exit;
	}
	++str;
	

	char_loop:
	j = 0;
	octet = 0;
	while(str != end){
		digit = atoi_table[*str];
		if(digit > 9){
			if(j == 0){
				errcode = 2;
				goto exit;
			}
			goto next_group;
		}
		octet = mul10(octet) + digit;
		++str;
		if(++j == 3) goto next_group;
	}
	if(i < 4) errcode = 1;

	exit:
	*plen = str - ip_string;
	return errcode;

}


struct hextet_string {
	const char *str;
	char len;
};

struct ipv6_parse_state {
	char idx;
	char idxtr; //compressed index
	struct hextet_string hextet[8];
};

//unspecified address = ::/128
//all-routers multicast = FF02::2
//type 133


void do_eui64(npxmac_t *mac_address)
{

}

/*
void ipv6_copy_parse_state(npxipv6_t *ip, struct ipv6_parse_state *state)
{
	register limit, i, ii;
	int n;

	i = 0;

	if(state->idxtr != -1){
		ii = state->idxtr;
		while(i < ii){
			npx_atoi32(&state->hextet[i].len,
				state->hextet[i].str, 16, &n);
			ip->hextet[i] = n;
			++i;
		}

		limit = 8 - (state->idx + 1) + i;
		while(i < limit){
			ip->hextet[i] = 0;
			++i;
		}

		while(i < 8){
			npx_atoi32(&state->hextet[ii].len,
				state->hextet[ii].str, 16, &n);
			ip->hextet[i] = n;	
			++i;
			++ii;
		}
	}
	else {
		while(i < 8){
			npx_atoi32(&state->hextet[i].len,
				state->hextet[i].str, 16, &n);
			ip->hextet[i] = n;
			++i;
		}
	}
}
*/

/*
int process_ipv6(npxipv6_t *ipv6, const char **ip_string,
		unsigned int plen, int errcode* ec)
{

	register i, j;
	register unsigned char digit;
	const char *str, *end;

	unsigned short hextet;
	char compressed = -1;
	int errcode = 0;

	struct ipv6_parse_state state;

	//assert(ip_string);
	//assert(plen);

	str = ip_string;

	if(plen){
		if(*plen < 3){
			errcode = 1;	
			goto exit;
		}
		end = str + *plen;
	}
	else {
		end = str + 39;	
	}

}
*/

int npx_ipv6_string(npxipv6_t *ipv6, const char *ip_string, unsigned int *plen)
{
	register i, j;
	register unsigned char digit;
	const char *str, *end;

	unsigned short hextet;
	char compressed = -1;
	int errcode = 0;

	struct ipv6_parse_state state;

	str = ip_string;


	if(*plen){
		if(*plen < 3){
			errcode = 1;
			goto exit;
		}
		end = str + *plen;
	}
	else end = str + 39;

	i = 0;

	if(*str == ':'){
		if(*(str+1) != ':'){
			errcode = 2;
			goto exit;
		}
		compressed = i++;
		str+=2;
	}
	goto char_loop;
	next_group:
	//store the previous hextet here
	printf("hextet %u: %u\n", i, hextet);
	if(++i > 7) goto exit;
	if(*str != ':'){
		errcode = 2;
		goto exit;
	}
	if(*(str-1) == ':'){
		if(compressed != -1) {
			errcode = 2;
			goto exit;
		}
		compressed = i++;	
	}
	++str;

	char_loop:
	j = 0;
	hextet = 0;
	while(str != end){
		//printf("char %c\n", *str);
		digit = atoi_table[*str];
		if(digit > 15){
			goto next_group;
		}
		hextet = mul16(hextet) + digit;
		++str;
		if(++j == 4) goto next_group;	
	}
	if(i < 8) errcode = 1;

	exit:
	*plen = str - ip_string;
	return errcode;






	/*
	state.idx = 0;
	state.idxtr = -1;

	i = 0;
	while(i < 7){
		state.hextet[i].str = str;
		ii = 0;
		while(ii < 4){
			digit = *str;
			if(!ishexdigit(digit)) break;
			++str;
			++ii;
		}
		state.hextet[i].len = ii;
		if(*str != ':') goto exit;
		++str;
		if(*str != ':') goto next;
		if(state.idxtr != -1) return 0;
		state.idxtr = i+1;
		++str;
	next:
		++i;
	}

	state.hextet[i].str = str;
	ii = 0;
	while(ii < 4){
		digit = *str;
		if(!ishexdigit(digit)) break;	
		++str;
		++ii;
	}
	state.hextet[i].len = ii;

exit:
	if((state.idxtr == -1 && i < 7)
	|| (state.idxtr != -1 && i == 7))
		return 0;

	if(ipv6){
		state.idx = i;
		ipv6_copy_parse_state(ipv6, &state);
	}

	if(*plen)  *plen = str - start;

	return string_success;
	*/
}
