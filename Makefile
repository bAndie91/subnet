
INSTALL_WRAPPER = 
PREFIX = /usr/local
BINPREFIX = $(PREFIX)/bin
ETCPREFIX = $(PREFIX)/etc
CIDR_FILE = $(ETCPREFIX)/cidr


.PHONY: default
default: subnet

subnet: src/subnet.c
	$(CC) -DCIDR_FILE=\"$(CIDR_FILE)\" $(CFLAGS) -o $@ $<

.PHONY: install
install: $(BINPREFIX)/subnet $(CIDR_FILE)

$(BINPREFIX)/subnet: subnet
	$(INSTALL_WRAPPER) install $< $@

$(CIDR_FILE): cidr.txt
	$(INSTALL_WRAPPER) cp $< $@
