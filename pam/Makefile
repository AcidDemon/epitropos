CC ?= gcc
# Hardening flags for a shared object dlopen'd into the PAM stack as root:
# FORTIFY + stack protector catch memory bugs; full RELRO/BIND_NOW and a
# non-exec stack shrink the exploitable surface; format-security rejects
# unchecked format strings at compile time.
CFLAGS = -Wall -Wextra -Werror -Wformat -Wformat-security -fPIC -O2 \
	-fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -shared -lpam -Wl,-z,relro,-z,now,-z,noexecstack

pam_epitropos.so: pam_epitropos.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f pam_epitropos.so

.PHONY: clean
