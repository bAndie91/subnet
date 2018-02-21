
#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <glob.h>

#define CIDR_FILE "/etc/cidr"
#define ADDRLEN_BY_AF(x) ( (((x) == AF_INET) ? sizeof(struct in_addr) : ((x) == AF_INET6) ? sizeof(struct in6_addr) : 0)*8 )
#define TRUE 1
#define FALSE 0



typedef struct ipaddr_t {
	int af;
	struct in_addr ip4;
	struct in6_addr ip6;
	int mask;
} ipaddr_t;

typedef int bool;

typedef enum walk_cidrs_event_t {
	WALK_NONE,
	WALK_ALIAS_FOUND,
	WALK_CIDR_FOUND,
	WALK_ERROR,
} walk_cidrs_event_t;

typedef enum walk_cidrs_control_t {
	WALK_RETURN,
	WALK_NEXT_ALIAS,
	WALK_CONTINUE,
} walk_cidrs_control_t;

typedef enum exit_code_t {
	EXIT_MATCH = EXIT_SUCCESS,
	EXIT_NO_MATCH = EXIT_FAILURE,
	EXIT_UNKNOWN_NETWORK,
	EXIT_PARSE_ERROR,
	EXIT_SYS_ERROR,
} exit_code_t;

typedef enum scan_mode_t {
	SCAN_NETNAME,
	SCAN_CIDR,
	SCAN_SUFFIX,
} scan_mode_t;




/* System functions */

bool EQ(char* a, char* b)
{
	if(a==NULL || b==NULL || strcmp(a,b) != 0) return FALSE;
	return TRUE;
}

void no_mem(int sz)
{
	warnx("Could not allocate %u bytes of memory.", sz);
	abort();
}

int glob_error(const char *epath, int eerrno)
{
	warn("glob: %s", epath);
	return -1;
}




/* Network functions */

int snmask(const char *cidr, ipaddr_t addr)
/* save mask value noted in cidr to addr, or return FALSE */
{
	const char *ptr;

	ptr = strchr(cidr, '/');
	if(ptr == NULL) return FALSE;
	ptr++;
	addr.mask = atoi(ptr);
	if(addr.mask > ADDRLEN_BY_AF(addr.af)) return FALSE;
	return TRUE;
}

int parseIpStr(const char *str, ipaddr_t addr)
/* convert str to machine-represented IP address and save into addr, also save address family */
{
	int ok;
	
	ok = inet_pton(AF_INET, str, &(addr.ip4));
	if(ok == -1) perror("inet_pton");
	addr.af = AF_INET;
	
	if(ok != 1)
	{
		ok = inet_pton(AF_INET6, str, &(addr.ip6));
		addr.af = AF_INET6;
	}
	
	if(ok == -1)
	{
		perror("inet_pton");
		exit(EXIT_PARSE_ERROR);
	}
	return ok;
}

int strToCidr(const char *str, ipaddr_t result_cidr)
{
	int ok = FALSE;
	char *tmp = strdup(str);
	if(tmp == NULL) no_mem(strlen(str));
	char *ptr = strchr(tmp, '/');
	if(ptr != NULL)	*ptr = '\0';
	
	if(parseIpStr(tmp, result_cidr) && snmask(str, result_cidr)) ok = TRUE;
	free(tmp);
	return ok;
}




/* File functions */

FILE *file_open(const char *path)
{
	FILE *fhnd;
	fhnd = fopen(path, "r");
	if(fhnd == NULL) err(EXIT_SYS_ERROR, "open %s", path);
	return fhnd;
}

void file_close(FILE *hnd)
{
	fclose(hnd);
}

void slurp_eol(FILE *fh)
{
	char c;
	while(!feof(fh) && (c = fgetc(fh)) != '\n');
}


bool in_subnet(ipaddr_t addr, ipaddr_t subnet)
{
	if(addr.af != subnet.af) return FALSE;
	if(subnet.mask == 0) return TRUE;
	
	int shift = ADDRLEN_BY_AF(addr.af) - subnet.mask;
	if(addr.af == AF_INET)
	{
		uint32_t a, n;
		a = ntohl(addr.ip4.s_addr);
		n = ntohl(subnet.ip4.s_addr);
		//fprintf(stderr, "Test [%08X] %08X in [%08X] %08X / %d\n", a, a & (-1UL << shift), n, n & (-1UL << shift), subnet.mask);
		return((a & (-1UL << shift)) == (n & (-1UL << shift)));
	}
	else if(addr.af == AF_INET6)
	{
		int off;
		int rmask = subnet.mask;
		bool ok = TRUE;
		for(off = 0; off < 16; off++)
		{
			uint8_t a, n, m;
			a = addr.ip6.s6_addr[off];
			n = subnet.ip6.s6_addr[off];
			m = 0xFF << (rmask >= 8 ? 0 : (8 - rmask));
			
			if(m == 0) break;
			
			//fprintf(stderr, "Test [%02X] %02X in [%02X] %02X / [%d] %d\n", a, a & m, n, n & m, subnet.mask, m);
			if((a & m) != (n & m))
			{
				ok = FALSE;
				break;
			}
			
			rmask -= 8;
			if(rmask < 0) rmask = 0;
		}
		return ok;
	}
	else
	{
		errx(EXIT_SYS_ERROR, "Unsupported Address Family 0x%X", addr.af);
	}
}



struct cb_data_FOR_all_cidrs {
	char *lookup_alias;
	bool found;
	walk_cidrs_control_t(*cb_func)(walk_cidrs_event_t, char*, ipaddr_t*, void*);
	void *cb_data;
	char *current_alias;
};

walk_cidrs_control_t walk_cb_all_cidrs(walk_cidrs_event_t event, char *network_alias, ipaddr_t *cidr, void *user_data_ptr)
/* find all CIDRs in a given network alias, then invoke the given callback function */
{
	struct cb_data_FOR_all_cidrs *user_data = user_data_ptr;
	
	if(event == WALK_ALIAS_FOUND)
	{
		if(user_data->found) return WALK_RETURN;
		if(EQ(network_alias, user_data->lookup_alias)) user_data->found = TRUE;
		else return WALK_NEXT_ALIAS;
	}
	else if(event == WALK_CIDR_FOUND)
	{
		return user_data->cb_func(event, user_data->current_alias, cidr, user_data->cb_data);
	}
	return WALK_CONTINUE;
}

void walk_cidrs(walk_cidrs_control_t(*callback_func)(walk_cidrs_event_t, char*, ipaddr_t*, void*), void *callback_data)
{
	char *cidr_file;
	FILE *cidr_fhnd;
	char *token_buf = NULL;
	char *current_netname = NULL;
	char lfbuf[2];
	ipaddr_t cidr;
	int tokens;
	walk_cidrs_event_t event;
	walk_cidrs_control_t ctrl;
	scan_mode_t scan_mode;
	bool do_wildcards;
	
	if((cidr_file = getenv("CIDR_FILE")) == NULL) cidr_file = CIDR_FILE;
	
	cidr_fhnd = file_open(cidr_file);
	scan_mode = SCAN_NETNAME;
	
	while(!feof(cidr_fhnd))
	{
		tokens = fscanf(cidr_fhnd, "%as%1[\n]", &token_buf, (char*)&lfbuf);
		event = WALK_NONE;
		ctrl = WALK_CONTINUE;
		do_wildcards = FALSE;
		
		if(tokens >= 1)
		{
			if(token_buf == NULL) no_mem(0);
			//warnx("token '%s'", token_buf);
			
			if(strlen(token_buf) == 0 || token_buf[0] == '#')
			{
				/* skip the rest of line */
				ctrl = WALK_NEXT_ALIAS;
			}
			else
			{
				if(scan_mode == SCAN_NETNAME)
				{
					if(token_buf[0] == '^')
					{
						current_netname = strdup((char*)(token_buf+1));
						scan_mode = SCAN_SUFFIX;
					}
					else
					{
						event = WALK_ALIAS_FOUND;
						current_netname = strdup(token_buf);
						scan_mode = SCAN_CIDR;
					}
					
					if(current_netname == NULL) no_mem(strlen(token_buf));
				}
				else if(scan_mode == SCAN_CIDR)
				{
					event = WALK_CIDR_FOUND;
					
					if(token_buf[0] == '/' || token_buf[0] == '.')
					{
						do_wildcards = TRUE;
					}
					else if(strToCidr(token_buf, cidr))
					{
						/* a CIDR found, will be passed to callback_func */
					}
					else
					{
						struct cb_data_FOR_all_cidrs cb_data;
						cb_data.current_alias = current_netname;
						cb_data.lookup_alias = token_buf;
						cb_data.found = FALSE;
						cb_data.cb_func = callback_func;
						cb_data.cb_data = callback_data;
						
						walk_cidrs(walk_cb_all_cidrs, (void*)&cb_data);
					}
				}
				else if(scan_mode == SCAN_SUFFIX)
				{
					do_wildcards = TRUE;
				}
				
				if(do_wildcards)
				{
					glob_t search_result;
					search_result.gl_offs = 0;
					size_t n_path;
					char *compound_alias;
					FILE *fh;
					char *cidr_str;
					
					int search = glob(token_buf, GLOB_ERR | GLOB_NOSORT, glob_error, &search_result);
					if(search != 0 && search != GLOB_NOMATCH)
					{
						errx(EXIT_SYS_ERROR, "glob error at '%s'", token_buf);
					}
					for(n_path = 0; n_path < search_result.gl_pathc; n_path++)
					{
						compound_alias = NULL;
						asprintf(&compound_alias, "%s%s", current_netname, (char*)(strrchr(search_result.gl_pathv[n_path], '/')+1));
						if(compound_alias == NULL) no_mem(0);
						
						ctrl = callback_func(WALK_ALIAS_FOUND, compound_alias, NULL, callback_data);
						if(ctrl == WALK_RETURN) break;
						else if(ctrl == WALK_NEXT_ALIAS) goto next_file;
						else if(ctrl == WALK_CONTINUE)
						{
							fh = file_open(search_result.gl_pathv[n_path]);
							while(!feof(fh) && fscanf(fh, "%as", &cidr_str))
							{
								if(cidr_str == NULL) no_mem(0);
								ctrl = WALK_CONTINUE;
								if(cidr_str[0] == '#')
								{
									/* ignore the rest of the line */
									slurp_eol(fh);
								}
								else if(strToCidr(cidr_str, cidr))
								{
									ctrl = callback_func(WALK_CIDR_FOUND, compound_alias, &cidr, callback_data);
								}
								else
								{
									errx(EXIT_PARSE_ERROR, "failed to parse cidr '%s'", cidr_str);
								}
								
								free(cidr_str);
								if(ctrl == WALK_RETURN) break;
								else if(ctrl == WALK_NEXT_ALIAS) break;
								else if(ctrl == WALK_CONTINUE);
								else errx(EXIT_SYS_ERROR, "Unknown callback code: %d", ctrl);
							}
							file_close(fh);
						}
						else
						{
							errx(EXIT_SYS_ERROR, "Unknown callback code: %d", ctrl);
						}
						
						next_file:
						free(compound_alias);
						if(ctrl == WALK_RETURN) break;
					}
					globfree(&search_result);
					if(ctrl == WALK_RETURN) break;
					if(scan_mode == SCAN_SUFFIX && ctrl == WALK_NEXT_ALIAS) ctrl = WALK_CONTINUE;
				}
			}
		}
		
		
		if(event != WALK_NONE)
		{
			ctrl = callback_func(event, token_buf, &cidr, callback_data);
		}
		
		
		if(ctrl == WALK_CONTINUE) /* no-op */;
		else if(ctrl == WALK_NEXT_ALIAS)
		{
			if(tokens == 1)
			{
				/* newline char was not read, read up to the EOL */
				slurp_eol(cidr_fhnd);
			}
			else if(tokens == 2)
			{
				/* newline is read, cidr_fhnd is pointing to the beginning of a new line */
			}
		}
		else if(ctrl == WALK_RETURN) break;
		else errx(EXIT_SYS_ERROR, "Unknown callback code: %d", ctrl);
		
		
		if(tokens >= 1)
		{
			free(token_buf);
			token_buf = NULL;
		}
		if(tokens == 2)
		{
			free(current_netname);
			current_netname = NULL;
			scan_mode = SCAN_NETNAME;
		}
	}
	
	free(token_buf);
	free(current_netname);
}


struct cb_data_FOR_print_if_match {
	ipaddr_t addr;
};

walk_cidrs_control_t walk_cb_print_if_match(walk_cidrs_event_t event, char *network_alias, ipaddr_t *cidr, void *user_data_ptr)
{
	struct cb_data_FOR_print_if_match *user_data = user_data_ptr;
	if(event == WALK_CIDR_FOUND)
	{
		if(in_subnet(user_data->addr, *cidr))
		{
			printf("%s\n", network_alias);
			return WALK_NEXT_ALIAS;
		}
	}
	return WALK_CONTINUE;
};


struct cb_data_FOR_stop_if_match {
	ipaddr_t addr;
	char **networks;  /* NULL-terminted list */
	int result;
};

walk_cidrs_control_t walk_cb_stop_if_match(walk_cidrs_event_t event, char *network_alias, ipaddr_t *cidr, void *user_data_ptr)
{
	struct cb_data_FOR_stop_if_match *user_data = user_data_ptr;
	size_t idx;
	
	if(event == WALK_ALIAS_FOUND)
	{
		for(idx = 0; user_data->networks[idx] != NULL; idx++)
		{
			if(EQ(network_alias, user_data->networks[idx]))
			{
				return WALK_CONTINUE;
			}
		}
		return WALK_NEXT_ALIAS;
	}
	else if(event == WALK_CIDR_FOUND)
	{
		if(in_subnet(user_data->addr, *cidr))
		{
			user_data->result = TRUE;
			return WALK_RETURN;
		}
	}
	return WALK_CONTINUE;
};


int main(int argc, char **argv)
{
	ipaddr_t addr;
	
	if(argc > 1)
	{
		if(!parseIpStr(argv[1], addr))
		{
			goto usage;
		}
	}
	
	if(argc == 2)
	{
		struct cb_data_FOR_print_if_match cb_data;
		cb_data.addr = addr;
		
		walk_cidrs(walk_cb_print_if_match, (void*)&cb_data);
		return EXIT_SUCCESS;
	}
	else if(argc > 2)
	{
		ipaddr_t check_cidr;
		int idx;
		char **aliases = NULL;
		int n_aliases = 0;
		
		aliases = malloc(sizeof(void*));
		if(aliases == NULL) no_mem(sizeof(void*));
		aliases[0] = NULL;
		
		/* First check given CIDRs */
		for(idx = 2; idx < argc; idx++)
		{
			if(strToCidr(argv[idx], check_cidr))
			{
				if(in_subnet(addr, check_cidr))
				{
					return EXIT_MATCH;
				}
			}
			else
			{
				aliases[n_aliases] = argv[idx];
				n_aliases++;
				aliases = realloc(aliases, sizeof(void*) * (n_aliases+1));
				if(aliases == NULL) no_mem(sizeof(void*) * (n_aliases+1));
				aliases[n_aliases] = NULL;
			}
		}
		
		if(n_aliases > 0)
		{
			struct cb_data_FOR_stop_if_match cb_data;
			cb_data.addr = addr;
			cb_data.networks = aliases;
			cb_data.result = FALSE;
			
			walk_cidrs(walk_cb_stop_if_match, (void*)&cb_data);
			
			if(cb_data.result)
			{
				return EXIT_MATCH;
			}
		}
		
		return EXIT_NO_MATCH;
	}
	else
	{
		usage:
		fprintf(stderr, "IPv4/IPv6 subnet check utility.\n"
"Usage: subnet <address> [<subnet> [<subnet> [<subnet> ...]]]\n"
"  Subnet definition must be in dotted-decimal (IPv4) or in colon-separated\n"
"  hexadecimal (IPv6) notation followed by a slash and decimal subnet mask\n"
"  or one of the well-known network aliases stored in %s.\n"
"  If no subnet given, lists all named subnets the address belongs to.\n"
"Exit code:\n"
"  %3d         one of the given subnets contains the address\n"
"  %3d         none contains the address\n"
"  %3d         parse error\n"
"  %3d         internal/system error\n"
"    *         other error\n"
"Environment:\n"
"  CIDR_FILE   path for network aliases file\n",
			CIDR_FILE, EXIT_MATCH, EXIT_NO_MATCH, EXIT_PARSE_ERROR, EXIT_SYS_ERROR);
	}
	return EXIT_SYS_ERROR;
}
