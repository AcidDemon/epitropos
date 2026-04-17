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
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define ENV_DIR "/var/run/epitropos"

static void get_path(char *buf, size_t len)
{
	snprintf(buf, len, "%s/pam.%d.env", ENV_DIR, (int)getpid());
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

	FILE *f = fopen(path, "w");
	if (!f)
		return PAM_SUCCESS;

	fchmod(fileno(f), 0640);

	if (rhost)
		fprintf(f, "PAM_RHOST=%s\n", rhost);
	if (service)
		fprintf(f, "PAM_SERVICE=%s\n", service);
	if (tty)
		fprintf(f, "PAM_TTY=%s\n", tty);
	if (user)
		fprintf(f, "PAM_USER=%s\n", user);

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
