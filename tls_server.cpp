/*
 * tls_server.cpp
 *
 * A demo multiprocess TLS server.
 */

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define BUF_SIZE 64
#define BACKLOG 8

const char *response =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/plain\r\n"
	"Connection: close\r\n"
	"Content-Length: 11\r\n"
	"\r\n"
	"hello world";

/*
 * Print OpenSSL error message, like perror
 */
void ssl_perror(const char *msg) {
	const char *err;
	err = ERR_error_string(ERR_get_error(), NULL);
	fprintf(stderr, "%s: %s\n", msg, err);
}

/*
 * Establish TLS and send "hello world" to the client.
 */
void handle_client(
	SSL_CTX *ssl_ctx,
	int peer_sockfd, 
	const struct sockaddr_in6 *peer_addr,
	socklen_t peer_addrlen
) {
	SSL *ssl_conn;
	int ret;
	char host[80];
	char svc[80];

	/*
	 * use getnameinfo() to print the name of our peer
	 */
	ret = getnameinfo(
		(struct sockaddr *)peer_addr, peer_addrlen,
		host, sizeof(host),
		svc, sizeof(svc),
		NI_NUMERICSERV
	);

	if (ret != 0) {
		fprintf(
			stderr, "getnameinfo() failed: %s\n",
			gai_strerror(ret)
		);
	} else {
		fprintf(
			stderr, "[process %d] accepted connection from %s:%s\n",
			getpid(), host, svc
		);
	}
	
	/* create a new SSL connection object */
	ssl_conn = SSL_new(ssl_ctx);
	if (ssl_conn == NULL) {
		ssl_perror("SSL_new");
		close(peer_sockfd);
		return;
	}

	/* attach the SSL connection object to our socket */
	if (SSL_set_fd(ssl_conn, peer_sockfd) != 1) {
		ssl_perror("ssl_set_fd");
		SSL_free(ssl_conn);
		close(peer_sockfd);
		return;
	}

	/* try to complete the SSL/TLS handshake */
	if (SSL_accept(ssl_conn) != 1) {
		ssl_perror("SSL_accept");
		SSL_free(ssl_conn);
		close(peer_sockfd);
		return;
	}

	/* 
	 * here, I'm ignoring the return value because this is a simple demo.
	 * In a real program you would not want to do this!
	 */
	SSL_write(ssl_conn, response, strlen(response));

	/* 
	 * SSL_shutdown may need to be called twice to shut down 
	 * both directions of the connection, according to its
	 * documentation. If it returns zero, it must be called
	 * again.
	 */
	while (SSL_shutdown(ssl_conn) == 0);

	/* Free the SSL connection. */
	SSL_free(ssl_conn);

	/* Finally, close the socket */
	close(peer_sockfd);

}

/*
 * Set up SA_NOCLDWAIT so we don't have to wait for children.
 */
void setup_sa_nocldwait( ) {
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));

	/* continue to use the default SIGCHLD handler */
	sa.sa_handler = SIG_DFL;
	/* don't turn children into zombies */
	sa.sa_flags = SA_NOCLDWAIT;

	if (sigaction(SIGCHLD, &sa, NULL) != 0) {
		perror("sigaction");
		fprintf(stderr, "warning: failed to set SA_NOCLDWAIT\n");
	}
}

SSL_CTX *create_ssl_context( ) {
	SSL_CTX *ret;

	/* 
	 * create a new SSL context.
	 * Note the use of SSLv23_server_method here instead of client.
	 */
	ret = SSL_CTX_new(SSLv23_server_method( ));
	
	if (ret == NULL) {
		fprintf(stderr, "SSL_CTX_new failed!\n");
		return NULL;
	}

	/* 
	 * set our desired options 
	 *
	 * Just like in the client, we will disable obsolete protocols.
	 * Note that we may not always want to do this on a server because
	 * we may block out obsolete clients. It's a tradeoff between
	 * security and compatibility.
	 */
	SSL_CTX_set_options(
		ret, 
		SSL_OP_NO_SSLv2 | 
		SSL_OP_NO_SSLv3 |
		SSL_OP_NO_COMPRESSION
	);

	/*
	 * We won't set any verification settings this time. Instead
	 * we need to give OpenSSL our certificate and private key.
	 */
	if (SSL_CTX_use_certificate_file(ret, "demo.crt", SSL_FILETYPE_PEM) != 1) {
		ssl_perror("SSL_CTX_use_certificate_file");
		SSL_CTX_free(ret);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ret, "demo.key", SSL_FILETYPE_PEM) != 1) {
		ssl_perror("SSL_CTX_use_PrivateKey_file");
		SSL_CTX_free(ret);
		return NULL;
	}

	/*
	 * Check that the certificate (public key) and private key match.
	 */
	if (SSL_CTX_check_private_key(ret) != 1) {
		fprintf(stderr, "certificate and private key do not match!\n");
		SSL_CTX_free(ret);
		return NULL;
	}

	return ret;
}

int main(int argc, char *argv[]) {
	/* note we now have 2 sockets */
	int listen_sockfd, peer_sockfd;

	/* our SSL context */
	SSL_CTX *ssl_ctx;

	struct sockaddr_in6 src, bindaddr;
	socklen_t srclen;

	pid_t child;

	setup_sa_nocldwait( );

	/* Initialize OpenSSL. */
	SSL_library_init( );
	SSL_load_error_strings( );

	ssl_ctx = create_ssl_context( );

	/* Create a stream socket. */
	listen_sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (listen_sockfd == -1) {
		perror("socket");
		return 1;
	}

	/* Set up the address to bind our socket to. */
	memset(&bindaddr, 0, sizeof(bindaddr));
	bindaddr.sin6_family = AF_INET6;
	bindaddr.sin6_port = htons(12345);
	memcpy(&bindaddr.sin6_addr, &in6addr_any, sizeof(in6addr_any));

	/* Bind the socket to the port. */
	if (bind(
		listen_sockfd, 
		(struct sockaddr *)&bindaddr, 
		sizeof(bindaddr)
	) != 0) {
		perror("bind");
		return 1;
	}

	/* Start listening. */
	if (listen(listen_sockfd, BACKLOG) != 0) {
		perror("listen");
		return 1;
	}

	/* Loop infinitely, accepting any connections we get. */
	for (;;) {
		/* call accept() to accept a connection */
		srclen = sizeof(src);
		peer_sockfd = accept(
			listen_sockfd, 
			(struct sockaddr *)&src, 
			&srclen
		);

		if (peer_sockfd < 0) {
			/* 
			 * the accept() may be interrupted by a signal handler
			 * this is expected, so we will not print a message
			 * in this case. We will just continue and try to 
			 * accept a connection again.
			 */
			if (errno != EINTR) {
				perror("accept");
			}
			continue;
		}

		child = fork();
		if (child == -1) {
			perror("fork");
		} else if (child == 0) {
			RAND_poll( );
			handle_client(ssl_ctx, peer_sockfd, &src, srclen);
			exit(0);
		}

		/* 
		 * if we get here, either the fork failed or 
		 * we are in the parent. Either way, we need to
		 * close the socket.
		 */
		close(peer_sockfd);

	}
}