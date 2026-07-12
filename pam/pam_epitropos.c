/*
 * pam_epitropos — stash PAM session variables for epitropos.
 *
 * Writes PAM_RHOST, PAM_SERVICE, PAM_TTY, PAM_USER to a per-session
 * file at /var/run/epitropos/pam.<pid>.env during open_session.
 * Epitropos reads this file at startup (keyed by getppid()) to
 * populate the kgv1 recording header with real PAM fields.
 *
 * Returns PAM_SUCCESS unconditionally — best-effort. If the write
 * fails, the session proceeds without PAM fields (same as before
 * this module existed).
 */

#include <security/pam_modules.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define ENV_DIR "/var/run/epitropos"

static void get_path(char *buf, size_t len)
{
	snprintf(buf, len, "%s/pam.%d.env", ENV_DIR, (int)getpid());
}

/*
 * Accept a PAM value only if it contains no control bytes. A value with an
 * embedded newline (e.g. a crafted rhost from unverified reverse DNS) would
 * otherwise inject a forged PAM_* line into the stash file that the proxy reads
 * into the recording header. Rejected fields are omitted.
 */
static int value_is_clean(const char *v)
{
	for (const unsigned char *p = (const unsigned char *)v; *p; p++) {
		if (*p < 0x20 || *p == 0x7f)
			return 0;
	}
	return 1;
}

static void write_field(FILE *f, const char *key, const char *val)
{
	if (val && value_is_clean(val))
		fprintf(f, "%s=%s\n", key, val);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
		    const char **argv)
{
	(void)flags;
	(void)argc;
	(void)argv;

	const char *rhost = NULL;
	const char *service = NULL;
	const char *tty = NULL;
	const char *user = NULL;

	pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);
	pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	pam_get_item(pamh, PAM_USER, (const void **)&user);

	char path[256];
	get_path(path, sizeof(path));

	/*
	 * O_EXCL | O_NOFOLLOW: never follow a symlink or open a pre-existing
	 * file — root must not be tricked into writing through a planted
	 * symlink even if the stash dir's ownership regresses. On a stale file
	 * left by a crashed prior session (pid reuse), unlink and retry once.
	 */
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0640);
	if (fd < 0) {
		unlink(path);
		fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0640);
		if (fd < 0)
			return PAM_SUCCESS;
	}

	FILE *f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		return PAM_SUCCESS;
	}

	/* Guarantee 0640 regardless of umask so the proxy (in the dir's group,
	 * via the setgid stash dir) can read the handoff. */
	fchmod(fileno(f), 0640);

	write_field(f, "PAM_RHOST", rhost);
	write_field(f, "PAM_SERVICE", service);
	write_field(f, "PAM_TTY", tty);
	write_field(f, "PAM_USER", user);

	fclose(f);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	char path[256];
	get_path(path, sizeof(path));
	unlink(path);
	return PAM_SUCCESS;
}
