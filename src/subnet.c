
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
#define MSG_INVALID_CB_CODE "Invalid callback code: %d"
#define SIZEOF_POINTER (sizeof(void*))



typedef struct ipaddr_t {
	int af;
	struct in_addr ip4;
	struct in6_addr ip6;
	int mask;
} ipaddr_t;

typedef int bool;

typedef enum walk_cidrs_event_t {
	WALK_NONE,
	WALK_INIT,
	WALK_ALIAS_FOUND,
	WALK_CIDR_FOUND,
	WALK_ALIAS_END,
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

#define MEMORY_EXCEPTION(b) memory_exception((b), __LINE__)
void memory_exception(const int, const unsigned int)
 __attribute__((cold, noreturn));
void memory_exception(const int sz, const unsigned int lineno)
{
	warnx("Could not allocate %d bytes of memory, line %d.", sz, lineno);
	abort();
}
#define MALLOC(b) abrealloc(NULL, (b), __LINE__)
#define REALLOC(p, b) abrealloc((p), (b), __LINE__)
void *abrealloc(const void *, const int, const unsigned int)
 __attribute__((malloc));
void *abrealloc(const void *old_ptr, const int sz, const unsigned int lineno)
{
	void *ptr = realloc((void*)old_ptr, sz);
	if(ptr == NULL) memory_exception(sz, lineno);
	return ptr;
}
#define STRDUP(p) abstrdup((p), __LINE__)
char *abstrdup(const char *, const unsigned int)
  __attribute__((malloc));
char *abstrdup(const char *ptr, const unsigned int lineno)
{
	char *dup = strdup(ptr);
	if(dup == NULL) memory_exception(strlen(ptr), lineno);
	return dup;
}


int glob_error(const char *, int)
 __attribute__((cold));
int glob_error(const char *epath, int eerrno)
{
	warn("glob: %s", epath);
	return -1;
}




/* Network functions */

int snmask(const char *cidr, ipaddr_t *addr)
/* save mask value noted in cidr to addr, or return FALSE */
{
	const char *ptr;

	ptr = strchr(cidr, '/');
	if(ptr == NULL) return FALSE;
	ptr++;
	addr->mask = atoi(ptr);
	if(addr->mask > ADDRLEN_BY_AF(addr->af)) return FALSE;
	return TRUE;
}

int parseIpStr(const char *str, ipaddr_t *addr)
/* convert str to machine-represented IP address and save into addr, also save address family */
{
	int ok;
	
	ok = inet_pton(AF_INET, str, &(addr->ip4));
	if(ok == -1) perror("inet_pton");
	addr->af = AF_INET;
	
	if(ok != 1)
	{
		ok = inet_pton(AF_INET6, str, &(addr->ip6));
		addr->af = AF_INET6;
	}
	
	if(ok == -1)
	{
		perror("inet_pton");
		exit(EXIT_PARSE_ERROR);
	}
	return ok;
}

int strToCidr(const char *str, ipaddr_t *result_cidr)
{
	int ok = FALSE;
	char *tmp = STRDUP(str);
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


bool in_subnet(const ipaddr_t addr, const ipaddr_t subnet)
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
	char *lookup_alias;  /* seek for this sepcific network name */
	walk_cidrs_control_t(*cb_func)(walk_cidrs_event_t, char*, ipaddr_t*, void*);  /* next level callback function called on each CIDR found */
	void *cb_data;  /* pointer passed to next level callback */
	char *current_alias;  /* pass this as network name to the next level callback */
	char **stack_of_aliases;
};

walk_cidrs_control_t walk_cb_all_cidrs(walk_cidrs_event_t event, char *network_alias, ipaddr_t *cidr, void *user_data_ptr)
/* find all CIDRs in a given network alias, then invoke the given callback function */
{
	struct cb_data_FOR_all_cidrs *user_data = user_data_ptr;
	
	if(event == WALK_ALIAS_FOUND)
	{
		if(EQ(network_alias, user_data->lookup_alias)) return WALK_CONTINUE;
		else return WALK_NEXT_ALIAS;
	}
	else if(event == WALK_CIDR_FOUND)
	{
		return user_data->cb_func(event, user_data->current_alias, cidr, user_data->cb_data);
	}
	else if(event == WALK_ALIAS_END)
	{
		return WALK_RETURN;
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
	bool was_eol;
	
	if((cidr_file = getenv("CIDR_FILE")) == NULL) cidr_file = CIDR_FILE;
	
	cidr_fhnd = file_open(cidr_file);
	scan_mode = SCAN_NETNAME;
	
	ctrl = callback_func(WALK_INIT, NULL, NULL, callback_data);
	if(ctrl == WALK_RETURN) goto end_walk_cidrs;
	
	while(!feof(cidr_fhnd))
	{
		tokens = fscanf(cidr_fhnd, "%as%1[\n]", &token_buf, (char*)&lfbuf);
		if(tokens == 2) was_eol = TRUE; else was_eol = FALSE;
		event = WALK_NONE;
		ctrl = WALK_CONTINUE;
		do_wildcards = FALSE;
		
		if(tokens >= 1)
		{
			if(token_buf == NULL) MEMORY_EXCEPTION(-1);
			//warnx("scan_mode %d tokens %d token_buf '%s'", scan_mode, tokens, token_buf);
			
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
						current_netname = STRDUP((char*)(token_buf+1));
						scan_mode = SCAN_SUFFIX;
					}
					else
					{
						event = WALK_ALIAS_FOUND;
						current_netname = STRDUP(token_buf);
						scan_mode = SCAN_CIDR;
					}
				}
				else if(scan_mode == SCAN_CIDR)
				{
					if(token_buf[0] == '/' || token_buf[0] == '.')
					{
						do_wildcards = TRUE;
					}
					else if(strToCidr(token_buf, &cidr))
					{
						/* a CIDR found, will be passed to callback_func */
						event = WALK_CIDR_FOUND;
					}
					else
					{
						/* probaby a nested alias name, go recursively */
						struct cb_data_FOR_all_cidrs cb_data = {
							.lookup_alias = token_buf,
							.current_alias = current_netname,
							.stack_of_aliases = NULL,
							.cb_func = callback_func,
							.cb_data = callback_data,
						};
						struct cb_data_FOR_all_cidrs *my_cb_data;
						int idx = 0;
						char **stack_of_aliases = NULL;
						
						/* detect recursion loop */
						if(callback_func == walk_cb_all_cidrs)
						{
							my_cb_data = (struct cb_data_FOR_all_cidrs *)callback_data;
							stack_of_aliases = my_cb_data->stack_of_aliases;
							
							for(idx = 0; stack_of_aliases[idx] != NULL; idx++)
							{
								if(EQ(stack_of_aliases[idx], cb_data.lookup_alias))
								{
									/* display path of loop */
									int idx2;
									for(idx2 = 0; stack_of_aliases[idx2] != NULL; idx2++) fprintf(stderr, "'%s' -> ", stack_of_aliases[idx2]);
									fprintf(stderr, "'%s' -> '%s'\n", cb_data.current_alias, cb_data.lookup_alias);
									errx(EXIT_PARSE_ERROR, "Recursion loop detected.");
								}
							}
						}
						
						/* save the network name currenly being processed */
						stack_of_aliases = REALLOC(stack_of_aliases, (idx+2) * SIZEOF_POINTER);
						stack_of_aliases[idx] = cb_data.current_alias;
						stack_of_aliases[idx+1] = NULL;
						cb_data.stack_of_aliases = stack_of_aliases;
						/* save new pointer of enlarged area of alias pointers to caller's userdata */
						if(callback_func == walk_cb_all_cidrs) my_cb_data->stack_of_aliases = stack_of_aliases;
						
						walk_cidrs(walk_cb_all_cidrs, (void*)&cb_data);
						
						if(callback_func != walk_cb_all_cidrs)
						{
							free(stack_of_aliases);
						}
						else
						{
							/* remove the pointer to the most recently processed alias */
							stack_of_aliases[idx] = NULL;
							/* leave area of alias pointers as large as it is */
						}
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
					char *reported_alias = current_netname;
					FILE *fh;
					char *cidr_str;
					
					int search = glob(token_buf, GLOB_ERR | GLOB_NOSORT, glob_error, &search_result);
					if(search != 0 && search != GLOB_NOMATCH) errx(EXIT_SYS_ERROR, "glob error at '%s'", token_buf);
					
					for(n_path = 0; n_path < search_result.gl_pathc; n_path++)
					{
						compound_alias = NULL;
						if(scan_mode == SCAN_SUFFIX)
						{
							char *suffix = strrchr(search_result.gl_pathv[n_path], '/') + 1;
							asprintf(&compound_alias, "%s%s", current_netname, suffix);
							if(compound_alias == NULL) MEMORY_EXCEPTION(strlen(current_netname) + strlen(suffix));
							reported_alias = compound_alias;
						}
						
						ctrl = callback_func(WALK_ALIAS_FOUND, reported_alias, NULL, callback_data);
						
						if(ctrl == WALK_RETURN) goto return_from_globbing;
						else if(ctrl == WALK_NEXT_ALIAS) goto next_file;
						else if(ctrl == WALK_CONTINUE)
						{
							fh = file_open(search_result.gl_pathv[n_path]);
							while(!feof(fh) && fscanf(fh, "%as", &cidr_str)>=1)
							{
								if(cidr_str == NULL) MEMORY_EXCEPTION(-1);
								ctrl = WALK_CONTINUE;
								if(cidr_str[0] == '#')
								{
									/* ignore the rest of the line */
									slurp_eol(fh);
								}
								else if(strToCidr(cidr_str, &cidr))
								{
									ctrl = callback_func(WALK_CIDR_FOUND, reported_alias, &cidr, callback_data);
								}
								else
								{
									errx(EXIT_PARSE_ERROR, "failed to parse cidr '%s'", cidr_str);
								}
								
								free(cidr_str);
								if(ctrl == WALK_RETURN) break;
								else if(ctrl == WALK_NEXT_ALIAS) break;
								else if(ctrl == WALK_CONTINUE) /* no-op */;
								else errx(EXIT_SYS_ERROR, MSG_INVALID_CB_CODE, ctrl);
							}
							file_close(fh);
							
							if(scan_mode == SCAN_SUFFIX)
							{
								ctrl = callback_func(WALK_ALIAS_END, reported_alias, NULL, callback_data);
								if(ctrl == WALK_RETURN) goto return_from_globbing;
								else if(ctrl == WALK_CONTINUE) /* no-op */;
								else errx(EXIT_SYS_ERROR, MSG_INVALID_CB_CODE, ctrl);
							}
						}
						else
						{
							errx(EXIT_SYS_ERROR, MSG_INVALID_CB_CODE, ctrl);
						}
						
						next_file:
						return_from_globbing:
						free(compound_alias);
						if(ctrl == WALK_RETURN) break;
						if(ctrl == WALK_NEXT_ALIAS && scan_mode != SCAN_SUFFIX) break;
					}
					globfree(&search_result);
					if(ctrl == WALK_RETURN) break;
					if(ctrl == WALK_NEXT_ALIAS && scan_mode == SCAN_SUFFIX) ctrl = WALK_CONTINUE;
				}
			}
		}
		
		
		if(event != WALK_NONE)
		{
			ctrl = callback_func(event, current_netname, &cidr, callback_data);
		}
		
		
		if(ctrl == WALK_CONTINUE)
		{
			if(was_eol)
			{
				walk_cidrs_control_t ctrl2 = callback_func(WALK_ALIAS_END, token_buf, &cidr, callback_data);
				if(ctrl2 == WALK_RETURN) break;
				else if(ctrl2 == WALK_CONTINUE) /* no-op */;
				else errx(EXIT_SYS_ERROR, MSG_INVALID_CB_CODE, ctrl2);
			}
		}
		else if(ctrl == WALK_NEXT_ALIAS)
		{
			if(!was_eol)
			{
				slurp_eol(cidr_fhnd);
				
				free(current_netname);
				current_netname = NULL;
				scan_mode = SCAN_NETNAME;
			}
		}
		else if(ctrl == WALK_RETURN) break;
		else errx(EXIT_SYS_ERROR, MSG_INVALID_CB_CODE, ctrl);
		
		
		if(tokens >= 1)
		{
			free(token_buf);
			token_buf = NULL;
		}
		
		if(was_eol)
		{
			free(current_netname);
			current_netname = NULL;
			scan_mode = SCAN_NETNAME;
		}
	}
	
	end_walk_cidrs:
	free(token_buf);
	free(current_netname);
	file_close(cidr_fhnd);
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
	char **networks;  /* NULL-terminted list, freed by caller */
	bool *networks_hit;  /* "networks"-sized, not terminated by NULL, freed by caller */
	int result;
};

walk_cidrs_control_t walk_cb_stop_if_match(walk_cidrs_event_t event, char *network_alias, ipaddr_t *cidr, void *user_data_ptr)
{
	struct cb_data_FOR_stop_if_match *user_data = user_data_ptr;
	size_t idx;
	
	if(event == WALK_ALIAS_FOUND)
	{
		if(user_data->networks[0] == NULL)
		{
			/* there are no more Network to check */
			return WALK_RETURN;
		}
		for(idx = 0; user_data->networks[idx] != NULL; idx++)
		{
			if(user_data->networks_hit[idx] == FALSE && EQ(network_alias, user_data->networks[idx]))
			{
				/* exclude this network name from future processing */
				user_data->networks_hit[idx] = TRUE;
				/* indicate that we want to get CIDRs of this Network */
				return WALK_CONTINUE;
			}
		}
		return WALK_NEXT_ALIAS;
	}
	else if(event == WALK_CIDR_FOUND)
	{
		if(in_subnet(user_data->addr, *cidr))
		{
			/* found a match */
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
		if(!parseIpStr(argv[1], &addr))
		{
			goto usage;
		}
	}
	
	if(argc == 2)
	{
		struct cb_data_FOR_print_if_match cb_data_printer = {
			.addr = addr,
		};
		
		walk_cidrs(walk_cb_print_if_match, (void*)&cb_data_printer);
		return EXIT_SUCCESS;
	}
	else if(argc > 2)
	{
		ipaddr_t check_cidr;
		size_t idx;
		char **aliases = NULL;
		int n_aliases = 0;
		
		/* First check given CIDRs */
		for(idx = 2; idx < argc; idx++)
		{
			if(strToCidr(argv[idx], &check_cidr))
			{
				if(in_subnet(addr, check_cidr))
				{
					return EXIT_MATCH;
				}
			}
			else
			{
				/* does not look like a CIDR, append it to the list of network names */
				n_aliases++;
				aliases = REALLOC(aliases, (n_aliases+1) * SIZEOF_POINTER);
				aliases[n_aliases-1] = argv[idx];
				aliases[n_aliases] = NULL;
			}
		}
		
		if(n_aliases > 0)
		{
			struct cb_data_FOR_stop_if_match cb_data_stopper = {
				.addr = addr,
				.networks = aliases,
				.result = FALSE,
				.networks_hit = NULL,
			};
			
			cb_data_stopper.networks_hit = MALLOC(n_aliases * sizeof(bool));
			for(idx = 0; idx < n_aliases; idx++) cb_data_stopper.networks_hit[idx] = FALSE;
			
			walk_cidrs(walk_cb_stop_if_match, (void*)&cb_data_stopper);
			
			if(cb_data_stopper.result)
			{
				return EXIT_MATCH;
			}
			else
			{
				for(idx = 0; idx < n_aliases; idx++)
				{
					if(!cb_data_stopper.networks_hit[idx])
					{
						warnx("Unknown netwrok: %s", cb_data_stopper.networks[idx]);
					}
				}
			}
			
			// free(cb_data_stopper.networks_hit)
		}
		// free(aliases)
		
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
"  %3d         none of subnets contain the address\n"
"  %3d         parse error\n"
"  %3d         internal/system error\n"
"    *         other error\n"
"Environment:\n"
"  CIDR_FILE   path for network aliases file\n",
			CIDR_FILE, EXIT_MATCH, EXIT_NO_MATCH, EXIT_PARSE_ERROR, EXIT_SYS_ERROR);
	}
	return EXIT_SYS_ERROR;
}
