/*
 * tls_client.cpp
 * 
 * Issue a (hard-coded) HTTPS request.
 *
 * Based on a sample from the OpenSSL wiki
 * (https://wiki.openssl.org/index.php/SSL/TLS_Client, retrieved 4/8/2015)
 */

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string>

#define BUF_SIZE 2048

const char *openssl_strerror( ) {
	return ERR_error_string(ERR_get_error(), NULL);
}

SSL_CTX *create_ssl_context( ) {
	SSL_CTX *ret;

	/* create a new SSL context */
	ret = SSL_CTX_new(SSLv23_client_method( ));
	
	if (ret == NULL) {
		fprintf(stderr, "SSL_CTX_new failed!\n");
		return NULL;
	}

	/* 
	 * set our desired options 
	 *
	 * We don't want to talk to old SSLv2 or SSLv3 servers because
	 * these protocols have security issues that could lead to the
	 * connection being compromised. 
	 *
	 * Return value is the new set of options after adding these 
	 * (we don't care).
	 */
	SSL_CTX_set_options(
		ret, 
		SSL_OP_NO_SSLv2 | 
		SSL_OP_NO_SSLv3 |
		SSL_OP_NO_COMPRESSION
	);

	/*
	 * set up certificate verification
	 *
	 * We want the verification to fail if the peer doesn't 
	 * offer any certificate. Otherwise it's easy to impersonate
	 * a legitimate server just by offering no certificate.
	 *
	 * No error checking, not because I'm being sloppy, but because
	 * these functions don't return error information.
	 */
	SSL_CTX_set_verify(
		ret, 
		SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		NULL
	);
	SSL_CTX_set_verify_depth(ret, 4);

	/*
	 * Point our context at the root certificates.
	 * This may vary depending on your system.
	 */
	if (SSL_CTX_load_verify_locations(ret, NULL, "/etc/ssl/certs") == 0) {
		fprintf(stderr, "Failed to load root certificates\n");
		SSL_CTX_free(ret);	
		return NULL;
	}

	return ret;
}

BIO *open_ssl_connection(SSL_CTX *ctx, const char *server) {
	BIO *ret;

	/* use our settings to create a BIO */
	ret = BIO_new_ssl_connect(ctx);
	if (ret == NULL) {
		fprintf(	
			stderr, 
			"BIO_new_ssl_connect failed: %s\n",
			openssl_strerror( )
		);
		return NULL;
	}

	/* according to documentation, this cannot fail */
	BIO_set_conn_hostname(ret, server);

	/* try to connect */
	if (BIO_do_connect(ret) != 1) {
		fprintf(stderr, 
			"BIO_do_connect failed: %s\n",
			openssl_strerror( )
		);

		BIO_free_all(ret);	
		return NULL;
	}

	/* try to do TLS handshake */
	if (BIO_do_handshake(ret) != 1) {
		fprintf(
			stderr, 
			"BIO_do_handshake failed: %s\n",
			openssl_strerror( )
		);

		BIO_free_all(ret);
		return NULL;
	}

	return ret;
}

int check_certificate(BIO *conn, const char *hostname) {
	SSL *ssl;
	X509 *cert;
	X509_NAME *subject_name;
	X509_NAME_ENTRY *cn;
	ASN1_STRING *asn1;
	unsigned char *cn_str;
	int pos;
	bool hostname_match;

	/* get this particular connection's TLS/SSL data */
	BIO_get_ssl(conn, &ssl);
	if (ssl == NULL) {
		fprintf(
			stderr, "BIO_get_ssl failed: %s\n",
			openssl_strerror( )
		);

		return -1;
	}

	/* get the connection's certificate */
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		/* no certificate was given - failure */
		return -1;
	}

	/* check that the certificate was verified */
	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		/* certificate was not successfully verified */
		return -1;
	}

	/* get the name of the certificate subject */
	subject_name = X509_get_subject_name(cert);
	
	/* and print it out */
	X509_NAME_print_ex_fp(stderr, subject_name, 0, 0);

	/* loop through "common names" (hostnames) in cert */
	pos = -1;
	hostname_match = false;
	for (;;) {
		/* move to next CN entry */
		pos = X509_NAME_get_index_by_NID(
			subject_name, NID_commonName, pos
		);

		if (pos == -1) { 
			break;
		}

		cn = X509_NAME_get_entry(subject_name, pos);
		asn1 = X509_NAME_ENTRY_get_data(cn);
		if (ASN1_STRING_to_UTF8(&cn_str, asn1) < 0) {
			fprintf(
				stderr, "ASN1_STRING_to_UTF8 failed: %s",
				openssl_strerror( )
			);
			return -1;
		}

		/* finally we have a hostname string! */
		if (strcmp((char *) cn_str, hostname) == 0) {
			hostname_match = true;
		}
	}

	if (hostname_match) {
		return 0;
	} else {
		fprintf(stderr, "hostnames do not match!\n");
		return -1;
	}
}

int main(int argc, const char *argv[]) {
	SSL_CTX *ctx;
	BIO *conn;
	int size;

	std::string hostname = "www.google.com";
	std::string port = "443";
	std::string destination = hostname + ":" + port;
	
	char buf[BUF_SIZE];
	char req[] = 
		"GET / HTTP/1.1\r\n"
		"Host: www.google.com\r\n"
		"Connection: close\r\n\r\n";

	/* 
	 * initialize OpenSSL 
	 * 
	 * The documentation for these functions indicates that they never
	 * return an error, and that it is safe to discard the return value.
	 */
	SSL_library_init( );
	SSL_load_error_strings( );

	/* Create the OpenSSL context */
	ctx = create_ssl_context( );
	if (ctx == NULL) {
		fprintf(stderr, "Failed to create SSL context\n");
		return 1;
	}

	/* Try to open an SSL connection */
	conn = open_ssl_connection(ctx, destination.c_str( ));
	if (conn == NULL) {
		fprintf(stderr, "Failed to create SSL connection\n");
		SSL_CTX_free(ctx);
		return 1;
	}

	if (check_certificate(conn, hostname.c_str( )) != 0) {
		fprintf(stderr, "Certificate tests failed\n");
		BIO_free_all(conn);
		SSL_CTX_free(ctx);
		return 1;
	}

	/* send request */
	BIO_puts(conn, req);

	/* receive response */
	do {
		size = BIO_read(conn, buf, BUF_SIZE);
		if (size > 0) {
			fwrite(buf, 1, size, stdout);
		}
	} while (size > 0 || BIO_should_retry(conn));

	BIO_free_all(conn);
	return 0;
}