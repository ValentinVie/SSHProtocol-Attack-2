/***********************************************************************

   File          : cse543-proto.c

   Description   : This is the network interfaces for the network protocol connection.

   Last Modified : 2018
   By            : Trent Jaeger

***********************************************************************/

/* Include Files */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

/* OpenSSL Include Files */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

/* Project Include Files */
#include "cse543-util.h"
#include "cse543-network.h"
#include "cse543-proto.h"
#include "cse543-ssl.h"
#include "formats/cse543-format-29.h"

/* Global */

struct A *perm_a = NULL; 


/* Functional Prototypes */

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type )
{
	struct rm_cmd *r;
	int rsize;
	int len; 

	assert(rptr != 0);
	assert(filename != 0);
	len = strlen( filename );

	rsize = sizeof(struct rm_cmd) + len;
	*rptr = r = (struct rm_cmd *) malloc( rsize );
	memset( r, 0, rsize );
	
	r->len = len;
	memcpy( r->fname, filename, r->len );  
	r->cmd = atoi( cmd );
	r->type = atoi( type );

	return 0;
}


/**********************************************************************

    Function    : get_message
    Description : receive data from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int get_message( int sock, ProtoMessageHdr *hdr, char *block )
{
	/* Read the message header */
	recv_data( sock, (char *)hdr, sizeof(ProtoMessageHdr), 
		   sizeof(ProtoMessageHdr) );
	hdr->length = ntohs(hdr->length);
	assert( hdr->length<MAX_BLOCK_SIZE );
	hdr->msgtype = ntohs( hdr->msgtype );
	if ( hdr->length > 0 )
		return( recv_data( sock, block, hdr->length, hdr->length ) );
	return( 0 );
}

/**********************************************************************

    Function    : wait_message
    Description : wait for specific message type from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
                  my - the message to wait for
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int wait_message( int sock, ProtoMessageHdr *hdr, 
                 char *block, ProtoMessageType mt )
{
	/* Wait for init message */
	int ret = get_message( sock, hdr, block );
	if ( hdr->msgtype != mt )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Server unable to process message type [%d != %d]\n", 
			 hdr->msgtype, mt );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return succesfully */
	return( ret );
}

/**********************************************************************

    Function    : send_message
    Description : send data over the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to send
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int send_message( int sock, ProtoMessageHdr *hdr, char *block )
{
     int real_len = 0;

     /* Convert to the network format */
     real_len = hdr->length;
     hdr->msgtype = htons( hdr->msgtype );
     hdr->length = htons( hdr->length );
     if ( block == NULL )
          return( send_data( sock, (char *)hdr, sizeof(ProtoMessageHdr) ) );
     else 
          return( send_data(sock, (char *)hdr, sizeof(ProtoMessageHdr)) ||
                  send_data(sock, block, real_len) );
}

/**********************************************************************

    Function    : encrypt_message
    Description : Generate ciphertext message for plaintext using key 
    Inputs      : plaintext - message
                : plaintext_len - size of message
                : key - symmetric key
                : buffer - encrypted message - includes tag
                : len - length of encrypted message and tag
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int encrypt_message( unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, 
		     unsigned char *buffer, unsigned int *len )
{
	unsigned char *ciphertext, *tag;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	unsigned int ivl = 16; //
	int clen = 0;

	ciphertext = (unsigned char *)malloc(plaintext_len);
	tag = (unsigned char *)malloc(TAGSIZE);
	clen = encrypt(plaintext, plaintext_len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	assert(( clen > 0 ) && ( clen <= plaintext_len ));

#if 0
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, clen);
	
	printf("Tag is:\n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);
#endif
	memcpy( buffer, tag, TAGSIZE );
	memcpy( buffer+TAGSIZE, iv, ivl );
	memcpy( buffer+TAGSIZE+ivl, ciphertext, clen );

	*len = clen+TAGSIZE+ivl;

	return ( 0 );
}



/**********************************************************************

    Function    : decrypt_message
    Description : Produce plaintext for given ciphertext buffer (ciphertext+tag) using key 
    Inputs      : buffer - encrypted message - includes tag
                : len - length of encrypted message and tag
                : key - symmetric key
                : plaintext - message
                : plaintext_len - size of message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int decrypt_message( unsigned char *buffer, unsigned int len, unsigned char *key, 
		     unsigned char *plaintext, unsigned int *plaintext_len )
{
	unsigned char *ciphertext, *iv,  *tag;
	unsigned int ivl = 16;
	unsigned int clen=0;
	int plen = 0;
  
	tag = (unsigned char *)buffer;
	iv = (unsigned char *)buffer+TAGSIZE; 
	ciphertext = (unsigned char *)buffer+TAGSIZE+ivl;
	clen = len-(TAGSIZE+ivl);

	/* decrypt */
	plen = decrypt(ciphertext, clen, (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext);
	assert( plen > 0 );
	*plaintext_len = plen;

	/* Show the decrypted text */
#if 1
	printf("Decrypted text is: \n");
	BIO_dump_fp (stdout, (const char *)plaintext, (int)*plaintext_len);
#endif
	
	return 0;
}



/**********************************************************************

    Function    : extract_public_key
    Description : Create public key data structure from network message
    Inputs      : buffer - network message  buffer
                : size - size of buffer
                : pubkey - public key pointer
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int extract_public_key( char *buffer, unsigned int size, EVP_PKEY **pubkey )
{
	RSA *rsa_pubkey = NULL;
	FILE *fptr;

	*pubkey = EVP_PKEY_new();

	/* Extract server's public key */
	/* Make a function */
	fptr = fopen( PUBKEY_FILE, "w+" );

	if ( fptr == NULL ) {
		errorMessage("Failed to open file to write public key data");
		return -1;
	}

	fwrite( buffer, size, 1, fptr );
	rewind(fptr);

	/* open public key file */
	if (!PEM_read_RSAPublicKey( fptr, &rsa_pubkey, NULL, NULL))
	{
		errorMessage("Cliet: Error loading RSA Public Key File.\n");
		return -1;
	}

	if (!EVP_PKEY_assign_RSA(*pubkey, rsa_pubkey))
	{
		errorMessage("Client: EVP_PKEY_assign_RSA: failed.\n");
		return -1;
	}

	fclose( fptr );
	return 0;
}


/**********************************************************************

    Function    : generate_pseudorandom_bytes
    Description : Generate pseudirandom bytes using OpenSSL PRNG 
    Inputs      : buffer - buffer to fill
                  size - number of bytes to get
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int generate_pseudorandom_bytes( unsigned char *buffer, unsigned int size)
{
	int rc = RAND_load_file("/dev/urandom", 32);
	if(rc != 32) {
		/* RAND_load_file failed */
		return -1;
	}
	rc = RAND_bytes(buffer, size);
	unsigned long err = ERR_get_error();

	if(rc != 1) {
		/* RAND_bytes failed */
		/* `err` is valid    */
		return err;
	}

	/* OK to proceed */ 
	return 0;
}


/**********************************************************************

    Function    : seal_symmetric_key
    Description : Encrypt symmetric key using public key
    Inputs      : key - symmetric key
                  keylen - symmetric key length in bytes
                  pubkey - public key
                  buffer - output buffer to store the encrypted seal key and ciphertext (iv?)
    Outputs     : len if successful, -1 if failure

***********************************************************************/

int seal_symmetric_key( unsigned char *key, unsigned int keylen, EVP_PKEY *pubkey, char *buffer )
{
	int rc = 0;
	unsigned char *ciphertext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;

	// rc is ciphertext len
	rc = rsa_encrypt( key, keylen, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );
	assert( rc > 0 );
	// assert ekeylen

	/* need to buffer:  encrypted key (256 bytes), iv (16 bytes), and ciphertext (48 bytes) */
	memcpy( buffer, ek, ekl );
	memcpy( buffer+ekl, iv, ivl );
	memcpy( buffer+ekl+ivl, ciphertext, rc );

	return ( rc + ekl + ivl );
}

/**********************************************************************

    Function    : unseal_symmetric_key
    Description : Perform SSL unseal (open) operation to obtain the symmetric key
    Inputs      : buffer - buffer of crypto data for decryption (ek, iv, ciphertext)
                  len - length of buffer
                  pubkey - public key 
                  key - symmetric key (plaintext from unseal)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int unseal_symmetric_key( char *buffer, unsigned int len, EVP_PKEY *privkey, unsigned char **key )
{
	unsigned char *ciphertext;
	unsigned char *ek;
	unsigned int ekl = 256;  //
	unsigned char *iv;
	unsigned int ivl = 16;   //
	unsigned int clen = 0;

	// decompose buffer
	ek = (unsigned char *)buffer;
	iv = (unsigned char *)(buffer+ekl);
	ciphertext = (unsigned char *)(buffer+ekl+ivl);
	clen = (len - (ekl + ivl));

	// decrypt - create fresh "key" buffer
	rsa_decrypt( ciphertext, clen, ek, ekl, iv, ivl, key, privkey );

	return( 0 );
}


/* 

  CLIENT FUNCTIONS 

*/



/**********************************************************************

    Function    : client_authenticate
    Description : this is the client side of the exchange
    Inputs      : sock - server socket
                  session_key - the key resulting from the exchange
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/


int client_authenticate( int sock, unsigned char **session_key )
{
	/* Local variables */
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	EVP_PKEY *pubkey;
	unsigned char *key, *plaintext;
	unsigned int plen = 0;
	unsigned int ciphertext_len = 0;
	int rc = 0;

	/* initialize */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	/* Set everything up */
	hdr.msgtype = CLIENT_INIT_EXCHANGE;
	hdr.length = 0;
	printf("client: send init exchange\n");
	send_message( sock, &hdr, NULL );

	/* Wait for ack message, extract server's public key (nonce? server depends on client, whose secrecy is at risk) */
	printf("client:  Wait for server init response\n");
        wait_message( sock, &hdr, block, SERVER_INIT_RESPONSE );
	rc = extract_public_key( block, hdr.length, &pubkey );

	if ( rc < 0 ) {
		errorMessage("Client: Failed to extract server public key correctly\n");
		return -1;
	}
	     
	/* Produce random number for key - unlike SSH, 128 bits for main and HMAC key */
	key = (unsigned char *)malloc( KEYSIZE );
	rc = generate_pseudorandom_bytes( key, KEYSIZE );

#if 1
	printf("Symmetric Key is:\n");
	BIO_dump_fp (stdout, (const char *)key, KEYSIZE);
#endif

	if ( rc < 0 ) {
		errorMessage("Client: Failed to generate symmetric key correctly\n");
		return -1;
	}

	/* Encrypt symmetric key with server's public key into block */
	ciphertext_len = seal_symmetric_key( key, KEYSIZE, pubkey, block );
	// keep the encrypted_key (at beginning of block) for checking as a nonce - and for decrypt

	if ( ciphertext_len < 0 ) {
		errorMessage("Client: Failed to seal symmetric key correctly\n");
		return -1;
	}

	/* Send the sealed symmetric key, wait for server ack */
	hdr.msgtype = CLIENT_INIT_ACK;
	hdr.length = ciphertext_len;
	printf("client: send ack with sealed key\n");
	send_message( sock, &hdr, block );

	/* Wait for ack message */
	printf("client: wait for server ack\n");
	wait_message( sock, &hdr, block, SERVER_INIT_ACK );
	plaintext = (unsigned char *)malloc( hdr.length );
	rc = decrypt_message( (unsigned char *)block, hdr.length, key, plaintext, &plen );
	assert( rc == 0 );

#if 1
	// receive 32 byte nonce
	printf("Nonce is:\n");
	BIO_dump_fp (stdout, (const char *)plaintext, plen);
#endif

	/* Build reply - add one to first byte */
	hdr.msgtype = CLIENT_CONFIRM;
	plaintext[0]++;

#if 1
	// receive 32 byte nonce
	printf("Nonce+1 is:\n");
	BIO_dump_fp (stdout, (const char *)plaintext, plen);
#endif

	rc = encrypt_message( plaintext, plen, key, (unsigned char *)block, &hdr.length );
	assert( rc == 0 );
	printf("client: send client confirmation (nonce+1)\n");
	send_message( sock, &hdr, block );

	/* Wait for server to reply message */
	// TJ: Nonce protection for freshness needed again
	printf("client: wait for server to confirm - then off we go\n");
	wait_message( sock, &hdr, block, SERVER_CONFIRM );
	rc = decrypt_message( (unsigned char *)block, hdr.length, key, plaintext, &plen );
	assert( rc == 0 );

#if 1
	// receive 32 byte nonce
	printf("Server confirm is:\n");
	BIO_dump_fp (stdout, (const char *)plaintext, plen);
#endif

	char test = 1;
	if ( memcmp( plaintext, &test, 1 ) != 0 ) {
		assert( 0 );
	}
	
	/* set session key */
	*session_key = key;

	/* Return succesfully */
	return( 0 );
}


/**********************************************************************

    Function    : transfer_file
    Description : transfer the entire file over the wire
    Inputs      : r - rm_cmd describing what to transfer and do
                  fname - the name of the file
                  sz - this is the size of the file to be read
                  key - the cipher to encrypt the data with
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int transfer_file( struct rm_cmd *r, char *fname, int sock, 
		   unsigned char *key )
{
	/* Local variables */
	int readBytes = 1, totalBytes = 0, fh;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	char outblock[MAX_BLOCK_SIZE];

	/* Read the next block */
	if ( (fh=open(fname, O_RDONLY, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		exit( -1 );
	}

	/* Send the command */
	hdr.msgtype = FILE_XFER_INIT;
	hdr.length = sizeof(struct rm_cmd) + r->len;
	send_message( sock, &hdr, (char *)r );

	/* Start transferring data */
	while ( ((r->cmd == CMD_CREATE) || (r->cmd == CMD_WRITE)) && (readBytes != 0) )
	{
		/* Read the next block */
		if ( (readBytes=read( fh, block, BLOCKSIZE )) == -1 )
		{
			/* Complain, explain, and exit */
			errorMessage( "failed read on data file.\n" );
			exit( -1 );
		}
		
		/* A little bookkeeping */
		totalBytes += readBytes;
		printf( "Reading %10d bytes ...\r", totalBytes );

		/* Send data if needed */
		if ( readBytes > 0 ) 
		{
#if 1
			printf("Block is:\n");
			BIO_dump_fp (stdout, (const char *)block, readBytes);
#endif

			/* Encrypt and send */
			encrypt_message( (unsigned char *)block, readBytes, key, 
					 (unsigned char *)outblock, &outbytes );
			hdr.msgtype = FILE_XFER_BLOCK;
			hdr.length = outbytes;
			send_message( sock, &hdr, outblock );
		}
	}
	// CMD_READ

	/* Send the ack, wait for server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );
	wait_message( sock, &hdr, block, EXIT );

	/* Clean up the file, return successfully */
	close( fh );
	return( 0 );
}


/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int client_secure_transfer( struct rm_cmd *r, char *fname, char *address ) 
{
	/* Local variables */
	unsigned char *key;
	int sock;

	sock = connect_client( address );
	// crypto setup, authentication
	client_authenticate( sock, &key );
	// symmetric key crypto for file transfer
	transfer_file( r, fname, sock, key );
	// Done
	close( sock );

	/* Return successfully */
	return( 0 );
}

/* 

  SERVER FUNCTIONS 

*/

/**********************************************************************

    Function    : test_rsa
    Description : test the rsa encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_rsa( EVP_PKEY *privkey, EVP_PKEY *pubkey )
{
	unsigned int len = 0;
	unsigned char *ciphertext;
	unsigned char *plaintext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;

	printf("*** Test RSA encrypt and decrypt. ***\n");

	len = rsa_encrypt( (unsigned char *)"help me, mr. wizard!", 20, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, len);
#endif

	len = rsa_decrypt( ciphertext, len, ek, ekl, iv, ivl, &plaintext, privkey );

	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : test_aes
    Description : test the aes encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_aes( )
{
	int rc = 0;
	unsigned char *key;
	unsigned char *ciphertext, *tag;
	unsigned char *plaintext;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	int clen = 0, plen = 0;
	unsigned char msg[] = "Help me, Mr. Wizard!";
	unsigned int len = strlen((char *)msg);

	printf("*** Test AES encrypt and decrypt. ***\n");

	/* make key */
	key= (unsigned char *)malloc( KEYSIZE );
	rc = generate_pseudorandom_bytes( key, KEYSIZE );	
	assert( rc == 0 );

	/* perform encrypt */
	ciphertext = (unsigned char *)malloc( len );
	tag = (unsigned char *)malloc( TAGSIZE );
	clen = encrypt( msg, len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	assert(( clen > 0 ) && ( clen <= len ));

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, clen);
	
	printf("Tag is:\n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);
#endif

	/* perform decrypt */
	plaintext = (unsigned char *)malloc( clen+TAGSIZE );
	memset( plaintext, 0, clen+TAGSIZE ); 
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext );
	assert( plen > 0 );

	/* Show the decrypted text */
#if 0
	printf("Decrypted text is: \n");
	BIO_dump_fp (stdout, (const char *)plaintext, (int)plen);
#endif
	
	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : server_protocol
    Description : server processing of crypto protocol
    Inputs      : sock - server socket
                  key - the key resulting from the protocol
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int server_protocol( int sock, char *pubfile, EVP_PKEY *privkey, unsigned char **enckey )
{
	/* Local variables */
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];		
	unsigned int size;
	unsigned char *key, *nonce, *plaintext, *strptr;
	unsigned int plen = 0;
	int rc = 0;

	/* Wait for init message */
	printf("server: wait for client exchange...\n");
	wait_message( sock, &hdr, block, CLIENT_INIT_EXCHANGE );

	/* Send the public key file */
	size = buffer_from_file( pubfile, &strptr );  // TJ: Change types for this?
	assert ( size > 0 );

	hdr.msgtype = SERVER_INIT_RESPONSE;
	hdr.length = size;
	printf("server: send public key\n");
	send_message( sock, &hdr, (char *)strptr );

	/* Wait for client response - sealed symmetric key */
	printf("server: wait for client ack with symmetric key\n");
	wait_message( sock, &hdr, block, CLIENT_INIT_ACK );
	rc = unseal_symmetric_key( block, hdr.length, privkey, &key );

#if 1
	printf("Symmetric Key is:\n");
	BIO_dump_fp (stdout, (const char *)key, 32);
#endif

	/* Use symmetric key to encrypt nonce */
	hdr.msgtype = SERVER_INIT_ACK;
	nonce = (unsigned char *)malloc( KEYSIZE );
	rc = generate_pseudorandom_bytes( nonce, KEYSIZE );	
	assert( rc == 0 );

#if 1
	printf("Nonce is:\n");
	BIO_dump_fp (stdout, (const char *)nonce, KEYSIZE);
#endif

	rc = encrypt_message( nonce, KEYSIZE, key, (unsigned char *)block, &hdr.length );
	assert( rc == 0 );
	printf("server: send encrypted nonce to check for freshness\n");
	send_message( sock, &hdr, block );

	/* Wait for client reply (nonce+1) message */
	printf("server: wait for client to confirm (nonce+1)\n");
	wait_message( sock, &hdr, block, CLIENT_CONFIRM );
	plaintext = (unsigned char *)malloc( hdr.length );
	rc = decrypt_message( (unsigned char *)block, hdr.length, key, plaintext, &plen );
	assert( rc == 0 );

#if 1
	printf("Nonce+1 is:\n");
	BIO_dump_fp (stdout, (const char *)plaintext, KEYSIZE);
#endif

	nonce[0]++;  // expected change to nonce
	if ( memcmp( plaintext, nonce, KEYSIZE ) != 0 ) {
		assert( 0 );  // always break
	}

	/* Send confirmation to client - first byte of plaintext is 1 */
	hdr.msgtype = SERVER_CONFIRM;
	plaintext[0] = 1;

#if 1
	printf("Nonce[0]==1 is:\n");
	BIO_dump_fp (stdout, (const char *)plaintext, KEYSIZE);
#endif

	rc = encrypt_message( plaintext, plen, key, (unsigned char *)block, &hdr.length );
	assert( rc == 0 );
	printf("server: reply to client\n");
	send_message( sock, &hdr, block );

	// set the key value from the protocol for receiving
	*enckey = key;

	/* Return succesfully */
	return( 0 );
}


/**********************************************************************

    Function    : receive_read
    Description : process request to read an object's field value and 
                  return encrypted value to requestor 
    Inputs      : r - request structure
                  sock - the socket to receive the file over
                  key - the cipher used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int receive_read( struct rm_cmd *r, int sock, unsigned char *key )
{
	return 0;
}

/**********************************************************************

    Function    : receive_write
    Description : receive a file over the wire, load into object data structure
    Inputs      : r - request structure
                  sock - the socket to receive the file over
                  key - the cipher used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int receive_write( struct rm_cmd *r, int sock, unsigned char *key )
{
	char buf[2*sizeof(struct A)];
	unsigned long totalBytes = 0;
	int done = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE];
	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_WRITE ) {

		/* allocate object memory for input object */
		struct A *a = (struct A *)calloc(0, sizeof(struct A)); 
		//char *buf = (char *)calloc(0, 2*sizeof(struct A)); 

		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", r->fname );
		while ( !done )
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
				/* Write the data file information */
				rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
						      plaintext, &outbytes );
				assert( rc  == 0 );

				memcpy(buf+totalBytes, plaintext, outbytes );

#if 1
				printf("Decrypted Block is:\n");
				BIO_dump_fp (stdout, (const char *)plaintext, outbytes);
#endif
				totalBytes += outbytes;
				printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */

		if (( totalBytes > (2*sizeof(struct A))) || (totalBytes < 0 ))
			return -1;

		/* start parsing the file input */
		int index;
		if ( sscanf ( buf, "struct A %d", &index) == 1 ) {
			a->index = index;
		}
		else assert( 0 );

		a->op0 = strcpy;
		upload_A( a, buf );		
		perm_a = a;
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		return( -1 );
	}

	return 0;
}


/**********************************************************************

    Function    : receive_upload
    Description : receive a file over the wire
    Inputs      : r - request structure
                  sock - the socket to receive the file over
                  key - the cipher used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

#define FILE_PREFIX "./shared/"

int receive_upload( struct rm_cmd *r, int sock, unsigned char *key )
{
	unsigned long totalBytes = 0;
	int done = 0, fh = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE];
	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_CREATE ) {

		/* open file for create */
		if ( r->type == TYP_DATA_SHARED ) {
			unsigned int size = r->len + strlen(FILE_PREFIX) + 1;
			char *fname = (char *)malloc( size );
			snprintf( fname, size, "%s%.*s", FILE_PREFIX, (int) r->len, r->fname );
			if ( (fh=open( fname, O_WRONLY|O_CREAT|O_TRUNC, 0700)) > 0 );
			else assert( 0 );
		}
		else assert( 0 );

		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", r->fname );
		while ( !done )
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
				/* Write the data file information */
				rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
						      plaintext, &outbytes );
				assert( rc  == 0 );
				write( fh, plaintext, outbytes );

				printf("Decrypted Block is:\n");
				BIO_dump_fp (stdout, (const char *)plaintext, outbytes);

				totalBytes += outbytes;
				printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */
		close( fh );
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		return( -1 );
	}
	
	return 0;
}


/**********************************************************************

    Function    : receive_file
    Description : receive a file over the wire
    Inputs      : sock - the socket to receive the file over
                  key - the cipher used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int receive_file( int sock, unsigned char *key ) 
{
	/* Local variables */
	ProtoMessageHdr hdr;
	struct rm_cmd *r = NULL;
	char block[MAX_BLOCK_SIZE];
	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* Receive the init message */
	wait_message( sock, &hdr, block, FILE_XFER_INIT );

	/* set command structure */
	struct rm_cmd *tmp = (struct rm_cmd *)block;
	unsigned int len = tmp->len;
	r = (struct rm_cmd *)malloc( sizeof(struct rm_cmd) + len );
	r->cmd = tmp->cmd, r->type = tmp->type, r->len = len;
	memcpy( r->fname, tmp->fname, len );

	// perform commands
	switch( r->cmd ) {
	case CMD_CREATE:
		rc = receive_upload( r, sock, key );
		break;
	case CMD_WRITE:
		rc = receive_write( r, sock, key );
		break;
	case CMD_READ:
		rc = receive_read( r, sock, key );
	default:
		break;
	}

	assert( rc == 0 );
	
	/* Server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );

	return( 0 );
}

/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : pubkey - public key of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int server_secure_transfer( char *privfile, char *pubfile )
{
	/* Local variables */
	int server, errored, newsock;
	RSA *rsa_privkey = NULL, *rsa_pubkey = NULL;
	RSA *pRSA = NULL;
	EVP_PKEY *privkey = EVP_PKEY_new(), *pubkey = EVP_PKEY_new();
	fd_set readfds;
	unsigned char *key;
	FILE *fptr;

	/* initialize */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	/* Connect the server/setup */
	server = server_connect();
	errored = 0;

	/* open private key file */
	fptr = fopen( privfile, "r" );
	assert( fptr != NULL);
	if (!(pRSA = PEM_read_RSAPrivateKey( fptr, &rsa_privkey, NULL, NULL)))
	{
		fprintf(stderr, "Error loading RSA Private Key File.\n");

		return 2;
	}

	if (!EVP_PKEY_assign_RSA(privkey, rsa_privkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr ); 

	/* open public key file */
	fptr = fopen( pubfile, "r" );
	assert( fptr != NULL);
	if (!PEM_read_RSAPublicKey( fptr , &rsa_pubkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Public Key File.\n");
		return 2;
	}

	if (!EVP_PKEY_assign_RSA( pubkey, rsa_pubkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr );

	// Test the RSA encryption and symmetric key encryption
	test_rsa( privkey, pubkey );
	test_aes();

	/* Repeat until the socket is closed */
	while ( !errored )
	{
		FD_ZERO( &readfds );
		FD_SET( server, &readfds );
		if ( select(server+1, &readfds, NULL, NULL, NULL) < 1 )
		{
			/* Complain, explain, and exit */
			char msg[128];
			sprintf( msg, "failure selecting server connection [%.64s]\n",
				 strerror(errno) );
			errorMessage( msg );
			errored = 1;
		}
		else
		{
			/* Accept the connect, receive the file, and return */
			if ( (newsock = server_accept(server)) != -1 )
			{
				/* Do the protocol, receive file, shutdown */
				server_protocol( newsock, pubfile, privkey, &key );
				receive_file( newsock, key );
				close( newsock );
			}
			else
			{
				/* Complain, explain, and exit */
				char msg[128];
				sprintf( msg, "failure accepting connection [%.64s]\n", 
					 strerror(errno) );
				errorMessage( msg );
				errored = 1;
			}
		}
	}

	/* Return successfully */
	return( 0 );
}



/* other stuff */

void test_attack( void )
{
	system("/bin/ls");
}
