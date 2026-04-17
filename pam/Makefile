CC ?= gcc
CFLAGS = -Wall -Wextra -Werror -fPIC -O2
LDFLAGS = -shared -lpam

pam_epitropos.so: pam_epitropos.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f pam_epitropos.so

.PHONY: clean
