/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011, 2012, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define SIG1	"v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n" \
	"    d=football.example.com; i=@football.example.com;\r\n" \
	"    q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n" \
	"    subject : date : message-id : from : subject : date;\r\n" \
	"    bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" \
	"    b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r\n" \
	"    Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r\n"

#define SIG2	"v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n" \
	"    d=football.example.com; i=@football.example.com;\r\n" \
	"    q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r\n" \
	"    date : message-id : from : subject : date;\r\n" \
	"    bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" \
	"    b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r\n" \
	"    DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r\n" \
	"    dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=\r\n"

#define RFC8463_RSA_SELECTOR	SELECTOR
#define RFC8463_ED25519_SELECTOR	SELECTOR2
#define RFC8463_DOMAIN	"football.example.com"

int kl;

/*
**  KEY_LOOKUP_RFC8463 -- key lookup (allows ed25519 key)
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	buf -- where to write the result
**  	buflen -- how much space is available at "buf"
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
key_lookup_rfc8463(DKIM *dkim, DKIM_SIGINFO *sig, unsigned char *buf,
                   size_t buflen)
{
	const char *selector;
	const char *domain;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(buf != NULL);

	selector = dkim_sig_getselector(sig);
	assert(selector != NULL);
	assert(strcmp(selector, RFC8463_ED25519_SELECTOR) == 0 ||
	       strcmp(selector, RFC8463_RSA_SELECTOR) == 0);

	domain = dkim_sig_getdomain(sig);
	assert(domain != NULL);
	assert(strcmp(domain, RFC8463_DOMAIN) == 0);

	memset(buf, '\0', buflen);
	if(strcmp(selector, RFC8463_ED25519_SELECTOR) == 0)
	{
		strncpy(buf, RFC8463_ED25519PUBLICKEY, buflen);
	}
	else
	{
		strncpy(buf, RFC8463_RSAPUBLICKEY, buflen);
	}

	kl++;

	return DKIM_STAT_OK;
}

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	The usual.
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
#ifdef TEST_KEEP_FILES
	u_int flags;
#endif /* TEST_KEEP_FILES */
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO **sigs;
	int nsigs;
	dkim_alg_t alg[2];
	unsigned int bits[2];
	unsigned char hdr[MAXHEADER + 1];

	kl = 0;

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	if (!dkim_libfeature(lib, DKIM_FEATURE_ED25519) ||
	    !dkim_libfeature(lib, DKIM_FEATURE_SHA256))
	{
		printf("*** relaxed/relaxed ed25519-sha256/rsa-sha256 rfc8463 example verifying SKIPPED\n");
		dkim_close(lib);
		return 0;
	}

	printf("*** relaxed/relaxed ed25519-sha256/rsa-sha256 rfc8463 example verifying\n");

#ifdef TEST_KEEP_FILES
	/* set flags */
	flags = (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);
#endif /* TEST_KEEP_FILES */

	/* supply the right pubkey above */
	status = dkim_set_key_lookup(lib, key_lookup_rfc8463);
	assert(status == DKIM_STAT_OK);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG1);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, THEADER00, strlen(THEADER00));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, THEADER01, strlen(THEADER01));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, THEADER02, strlen(THEADER02));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, THEADER03, strlen(THEADER03));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, THEADER04, strlen(THEADER04));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, THEADER05, strlen(THEADER05));
	assert(status == DKIM_STAT_OK);

	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, TBODY, strlen(TBODY));
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, NULL);
	/* save dkim_eom status to be checked below, after sig results */

	nsigs = 0;
	assert(dkim_getsiglist(dkim, &sigs, &nsigs) == DKIM_STAT_OK);
	assert(nsigs == 2);

	assert(dkim_sig_getsignalg(sigs[0], &alg[0]) == DKIM_STAT_OK);
	assert(dkim_sig_getsignalg(sigs[1], &alg[1]) == DKIM_STAT_OK);
	assert(alg[0] == DKIM_SIGN_RSASHA256 || alg[1] == DKIM_SIGN_RSASHA256);
	assert(alg[0] == DKIM_SIGN_ED25519SHA256 || alg[1] == DKIM_SIGN_ED25519SHA256);

	assert(dkim_sig_getkeysize(sigs[0], &bits[0]) == DKIM_STAT_OK);
	assert(dkim_sig_getkeysize(sigs[1], &bits[1]) == DKIM_STAT_OK);
	if(alg[0] == DKIM_SIGN_RSASHA256)
	{
		assert(bits[0] == 1024);
		assert(bits[1] == 256);
	}
	else
	{
		assert(bits[0] == 256);
		assert(bits[1] == 1024);
	}

	assert(dkim_sig_geterror(sigs[0]) == DKIM_SIGERROR_OK);
	assert(dkim_sig_geterror(sigs[1]) == DKIM_SIGERROR_OK);

	/* Now assert dkim_eom() success */
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	assert(kl == 2);

	dkim_close(lib);

	return 0;
}
