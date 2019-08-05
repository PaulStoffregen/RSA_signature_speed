#include "local_rsa.h"
#include "local_sha256.h"
#include "local_rsa_sign.h"

#include <stdio.h>
#include <string.h>


static mbedtls_rsa_context rsa;

/*  How to create a RSA private key in the format used below:

1: Create a RSA private key.  This file will begin "-----BEGIN PRIVATE KEY-----"

	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out mykey.key

2: Export the public key.  This file will begin "-----BEGIN PUBLIC KEY-----"

	openssl rsa -in mykey.key -pubout -out mykey.pub

3: Convert the private key to PEM PKCS#1 format.  This file will begin
   "-----BEGIN RSA PRIVATE KEY-----"

	openssl rsa -in mykey.key -out mykey.pem -outform PEM

4: Extract raw ASN1 data

	openssl asn1parse -in mykey.pem > mykey.asn1

5: Reduce the raw data to a nicer format

	./asn1_to_txt.pl mykey.asn1

6: Manually copy the first 5 lines into the code below.  The last 3 are not used.

*/

int rsa_init(void)
{
	mbedtls_mpi N, P, Q, D, E;

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&E);

	mbedtls_mpi_read_string(&N, 16, "B439E9E9D3523030E2F5C4884E98C989429F0952F3E8E06050DD731137CD463CDFB6A4D784F9FE5770B93E50F5CDF4932C04CCAD640C7D5F3DFEF7DCF573885CDCFE7189620BD4B81F1731570B13B3A0CB2C676E66684E3CF608BF58E788E9CD4E801DBA57863DBE0022532B7807D4CDDF6A35E118FDF0049C14DC0EABF3B808E913FEB018C637EBC3C69893FC21C70FEDDDF7F0663808739150B9522C80B9D84EB2D265596CC058107198E2E22EC8C86831120801A64AAA2749003B0C090F25050658F23329246BD38865AC4CE4B91361490AF62D01C032400E54A6C3B553D88C5BE61DECADF2CDCDBFFD8A743B7F9638305D8CC413AFE649947AD17E33237D");
	mbedtls_mpi_read_string(&E, 16, "010001");
	mbedtls_mpi_read_string(&D, 16, "7157468ADD71FF8A8F011EA2D642F1E397792AC4F74D89E62894CBEB951B4C43B63147C39E0615F4E99825DF86660A9C8F7F4934F60980C2E7DB3407CA78E8D5F5C9329FC2804C3BAA99CC56C049989AD38B4E54B8A47A278E56FBF72E4D05342F5D14D4FE7C16D229856CA696AADE22C69125E734EF6605901EF2316BE42EE4A3EB85116B3513585F67F6A7C51700BBF969D5B0D245207B580531BECD63ACEA71D120FD92FE8AF2C64C2C613979928461537EC55871309890A5F5EAD8779599D536A434D0D413FB971788CEDA01BFAFB9B35E4B054BF3CC9A9A372EB48A2DB9923B6888A290119A715E6C1CE961DB7EEC3B6E5D0C573693606DE7D6A5070BE5");
	mbedtls_mpi_read_string(&P, 16, "EF385935C0DBBBB351AC89FB1BAC11AEFCF6FF830A1CC37113571F072B619A84A8296B39E968CC10646A20FE051AEA25D31F64EC89ACC32F600CE09C5B253E78F081642F6084F951A258CC679DE6AFEBD49AA34456DB63A76656A5313736987E8FF4C7A9137241FBC92027D83A413A7DCAC2F26C8B73E501C75F58F34011AB07");
	mbedtls_mpi_read_string(&Q, 16, "C0DE37CC716DD53383F50FDC1758331706781A8DEB7A0E5744760133CC4A8E6A691737109471B5734C81647E58B2606D66E04BA70AC9E358C1DD70D0CB9EECC1DA1E13417D826ACB9CB40B24F9D29D3F90FC32203087F5A45B9F569B48CC68BADD45911ADBB36E847842F4278C9A28123C879545E1E007D8D1A14D0BBF6BE85B");

	if (mbedtls_rsa_import(&rsa, &N, &P, &Q, &D, &E) != 0) return 0;
	if (mbedtls_rsa_complete(&rsa) != 0) return 0;
	if (mbedtls_rsa_check_privkey(&rsa) != 0) return 0;

	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&P);
	mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&E);

	return 1;
}


// input is a 32 byte SHA256 hash
// output is a 256 byte buffer, for RSA2048 to encrypt
static void sha256_output_to_rsa2048_input(const unsigned char *input, unsigned char *output)
{
	static const unsigned char padding_and_asn1_stuff[224] = {
0x00,0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x30,0x31,0x30,
0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
	};
	memcpy(output, padding_and_asn1_stuff, 224);
	memcpy(output + 224, input, 32);
}

// plaintext is an ASCII string of any non-zero length
// output is a 256 byte buffer, receives 256 byte RSA signature
//
int rsa_sign_string(const char *plaintext, unsigned char *output)
{
	mbedtls_sha256_context sha256_ctx;
	unsigned char hash[32];
	unsigned char rsa_input[256];

	// first create SHA256 hash
	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts_ret(&sha256_ctx, 0);
	mbedtls_sha256_update_ret(&sha256_ctx, (const unsigned char *)plaintext, strlen(plaintext));
	mbedtls_sha256_finish_ret(&sha256_ctx, hash);
	mbedtls_sha256_free(&sha256_ctx);

	// then RSA encrypt the hash
	sha256_output_to_rsa2048_input(hash, rsa_input);
	mbedtls_rsa_private(&rsa, NULL, NULL, rsa_input, output);
	return 1;
}

