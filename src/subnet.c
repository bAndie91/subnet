
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>

#define NETNAME_MAX_LEN 63
#define CIDR_FILE "/etc/cidr"
#define ADDRLEN_BY_AF(x)	( (((x) == AF_INET) ? sizeof(struct in_addr) : ((x) == AF_INET6) ? sizeof(struct in6_addr) : 0)*8 )
#define YESSLURP 1
#define NOSLURP 0


char *cidr_file;
struct ipaddr {
	int af;
	struct in_addr ip4;
	struct in6_addr ip6;
	int mask;
};


/* Linked List functions */

struct linked_string {
	char *str;
	struct linked_string *next;
};

struct linked_string * linked_string_new()
{
	struct linked_string *lnk = malloc(sizeof(struct linked_string));
	lnk->str = NULL;
	lnk->next = NULL;
	return lnk;
}

struct linked_string * linked_string_seek(struct linked_string *lnk, unsigned int n)
{
	while(n > 0)
	{
		lnk = lnk->next;
		if(lnk == NULL) return NULL;
		n--;
	}
	return lnk;
}

char * linked_string_get(struct linked_string *lnk, unsigned int n)
{
	lnk = linked_string_seek(lnk, n);
	if(lnk == NULL) return NULL;
	return lnk->str;
}

void linked_string_set(struct linked_string *lnk, unsigned int n, char *str)
{
	lnk = linked_string_seek(lnk, n);
	if(lnk == NULL) return;
	free(lnk->str);
	lnk->str = strdup(str);
}

unsigned int linked_string_add(struct linked_string *lnk, const char *str)
{
	unsigned int n = 0;
	struct linked_string *newlnk;
	while(1)
	{
		if(lnk->str == NULL) break;
		n++;
		if(lnk->next == NULL) break;
		lnk = lnk->next;
	}
	if(n == 0)
	{
		newlnk = lnk;
	}
	else
	{
		newlnk = malloc(sizeof(struct linked_string));
		lnk->next = newlnk;
	}
	newlnk->str = strdup(str);
	newlnk->next = NULL;
	return n;
}

void linked_string_del(struct linked_string *lnk, unsigned int n)
{
	if(n == 0)
	{
		if(lnk->next == NULL)
		{
			free(lnk->str);
			lnk->str = NULL;
		}
		else
		{
			struct linked_string *second_lnk = lnk->next;
			lnk->str = second_lnk->str;
			lnk->next = second_lnk->next;
			free(second_lnk);
		}
	}
	else
	{
		struct linked_string *prev_lnk = linked_string_seek(lnk, n-1);
		lnk = prev_lnk->next;
		if(prev_lnk == NULL || lnk == NULL) return;
		free(lnk->str);
		prev_lnk->next = lnk->next;
		free(lnk);
	}
}


/* Network functions */

int snmask(const char *cidr, struct ipaddr *addr)
{
	const char *ptr;

	ptr = strchr(cidr, '/');
	if(ptr == NULL) return 0;
	ptr++;
	addr->mask = atoi(ptr);
	if(addr->mask > ADDRLEN_BY_AF(addr->af)) return 0;
	return 1;
}

int parseIpStr(const char *str, struct ipaddr *addr)
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
		exit(3);
	}
	return ok;
}


int strToCidr(const char *str, struct ipaddr *this_cidr)
{
	int ok = 0;
	char *tmp = strdup(str);
	char *ptr = strchr(tmp, '/');
	if(ptr != NULL)	*ptr = '\0';
	
	if(parseIpStr(tmp, this_cidr) && snmask(str, this_cidr)) ok = 1;
	free(tmp);
	return ok;
}

/* System functions */

void no_mem(int sz)
{
	errx(3, "Could not allocate %u bytes of memory.", sz);
}

void print_string_array(char **a)
{
	int i = 0;
	while(a[i] != NULL)
	{
		warnx("[%u] %p '%s'", i, a[i], a[i]);
		i++;
	}
	warnx("--");
}

/* File functions */

FILE * cidrfile_open()
{
	FILE *cidr_fhnd;
	cidr_fhnd = fopen(cidr_file, "r");
	if(cidr_fhnd == NULL) err(2, "open %s", cidr_file);
	return cidr_fhnd;
}

void cidrfile_close(FILE *hnd)
{
	fclose(hnd);
}

void slurp_eol(FILE *hnd)
{
	char c;
	while(!feof(hnd) && (c = fgetc(hnd)) != '\n');
}

int cidrfile_next_netname(FILE *hnd, char *namebuf, int doSlurp)
{
	while(1)
	{
		if(feof(hnd)) break;
		if(doSlurp && ftell(hnd) != 0) slurp_eol(hnd);
		if(fscanf(hnd, "%s", namebuf) == 1)
		{
			if(strlen(namebuf) == 0 || namebuf[0] == '#') continue;
			return 1;
		}
	}
	return 0;
}

int getCidrListByName(const char *netname, unsigned int *n_element, struct ipaddr **result_list, struct linked_string *alias_list)
{
	/*
		netname			string search for in CIDR list file
		n_element		pointer to an integer holding number of elements in result_list
		result_list		array of found CIDRs
		ptr_alias_stack	pointer to an array of strings each holding a subnet name to be resolved and terminated 
						by a NULL element, or ptr_alias_stack == NULL if there is no array initialized
		return			found: 1, not found: 0
	 */
	FILE *cidr_fhnd;
	char namebuf[NETNAME_MAX_LEN+1];
	char cidrbuf[512];
	char buf2[2];
	unsigned int n_hit = 0;
	int netname_found = 0;
	unsigned int i, alias_list_no;

	/* Maintain stack of aliases */
	if(alias_list == NULL)
	{
		alias_list = linked_string_new();
	}

	/* Check against resolving loop */
	i = 0;
	while(1)
	{
		char *str = linked_string_get(alias_list, i);
		if(str == NULL) break;
		if(strcmp(str, netname) == 0)
		{
			errx(2, "Subnet resolving loop detected at '%s'", netname);
		}
		i++;
	}
	alias_list_no = linked_string_add(alias_list, netname);
	
	
	/* Read file */
	cidr_fhnd = cidrfile_open();
	
	while(cidrfile_next_netname(cidr_fhnd, namebuf, NOSLURP))
	{
		if(strcmp(netname, namebuf)==0)
		{
			int tokens;
			netname_found = 1;

			/* Try to resolve named subnet */
			//warnx("NAME '%s'", namebuf);
			next_token:
				tokens = fscanf(cidr_fhnd, "%s%1[\n]", cidrbuf, buf2);
				if(tokens > 0)
				{
					//warnx("  CIDR '%s'", cidrbuf);
					struct ipaddr this_cidr;
					if(strToCidr(cidrbuf, &this_cidr))
					{
						/* cidrbuf is a valid subnet definition */
						int sz = sizeof(struct ipaddr) * ((*n_element) + 1);
						*result_list = (*n_element == 0) ? malloc(sz) : realloc(*result_list, sz);
						if(*result_list == NULL)
						{
							no_mem(sz);
						}
						memcpy(&(*result_list)[*n_element], &this_cidr, sizeof(struct ipaddr));
						n_hit++;
						(*n_element)++;
					}
					else
					{
						/* cidrbuf is a network name or an invalid subnet definition */
						if(!getCidrListByName(cidrbuf, n_element, result_list, alias_list))
						{
							errx(2, "Invalid CIDR definition '%s'", cidrbuf);
						}
					}
					
					/* Newline found */
					if(tokens >= 2) break;
					else goto next_token;
				}
			break;
		}
		else
		{
			slurp_eol(cidr_fhnd);
		}
	}
	
	cidrfile_close(cidr_fhnd);
	
	/* pop stack */
	linked_string_del(alias_list, alias_list_no);
	if(alias_list_no == 0)
	{
		free(alias_list);
	}

	return netname_found;
}

int in_subnet(struct ipaddr addr, struct ipaddr subnet)
{
	if(addr.af != subnet.af) return 0;
	if(subnet.mask == 0) return 1;
	
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
		int ok = 1;
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
				ok = 0;
				break;
			}
			
			rmask -= 8;
			if(rmask < 0) rmask = 0;
		}
		return ok;
	}
	else
	{
		errx(2, "Unsupported Address Family 0x%X", addr.af);
	}
}

int in_named_subnet(struct ipaddr addr, const char *netname)
{
	unsigned int c_net = 0, n_elem = 0;
	struct ipaddr *subnet_list;

	if(getCidrListByName(netname, &n_elem, &subnet_list, NULL))
	{
		while(c_net < n_elem)
		{
			if(in_subnet(addr, subnet_list[c_net])) return 0;
			c_net++;
		}
		free(subnet_list);
	}
	else
	{
		return 2;
	}
	return 1;
}


int main(int argc, char **argv)
{
	struct ipaddr addr;
	int c_arg = 2;

	if((cidr_file = getenv("CIDR_FILE")) == NULL) cidr_file = CIDR_FILE;

	if(argc > 1)
	{
		if(!parseIpStr(argv[1], &addr))
		{
			goto usage;
		}
	}
	
	if(argc == 2)
	{
		char netname[NETNAME_MAX_LEN+1];
		FILE *hnd = cidrfile_open();
		
		while(cidrfile_next_netname(hnd, netname, YESSLURP))
		{
			switch(in_named_subnet(addr, netname))
			{
				case 0:
					printf("%s\n", netname);
					break;
			}
		}
		cidrfile_close(hnd);
		return EXIT_SUCCESS;
	}
	else if(argc > 2)
	{
		while(c_arg < argc)
		{
			struct ipaddr this_cidr;
			if(strToCidr(argv[c_arg], &this_cidr))
			{
				if(in_subnet(addr, this_cidr)) return EXIT_SUCCESS;
			}
			else
			{
				switch(in_named_subnet(addr, argv[c_arg]))
				{
					case 0:
						return EXIT_SUCCESS;
						break;
					case 2:
						errx(3, "Unknown network '%s'", argv[c_arg]);
						break;
				}
			}
			c_arg++;
		}
		return EXIT_FAILURE;
	}
	else
	{
		usage:
		fprintf(stderr, "IPv4/IPv6 subnet check utility.\n"
"Usage: subnet <address> [<subnet> [<subnet> [<subnet> ...]]]\n"
"  Subnet definition must be in dotted-decimal (IPv4) or in colon-separated\n"
"  hexadecimal (IPv6) notation followed by a slash and decimal subnet mask\n"
"  or one of the well-known network aliases stored in %s.\n"
"  If no subnet given, it lists all named subnets the address belongs to.\n"
"Exit code:\n"
"  %3d         one of the given subnets contains the address\n"
"  %3d         none contains the address\n"
"  %3d         unknown subnet name given\n"
"    *         error\n"
"Envirnment:\n"
"  CIDR_FILE   path for network aliases file\n",
			CIDR_FILE, EXIT_SUCCESS, EXIT_FAILURE, 3);
	}
	return 2;
}
