#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"

#include "necrolog.h"

#include <iostream>

int main(int argc, char *argv[])
{
	enum class Command {ENCRYPT, DECRYPT, HELP};
	Command command = Command::HELP;;
	std::string pub_key_file;
	std::string pri_key_file;
	std::string certificate_file;
	bool o_no_input = false;
	for (int i = 1; i < argc; ++i) {
		std::string arg(argv[i]);
		if(arg == "-h")
			command = Command::HELP;
		else if(arg == "-c" || arg == "--certificate") {
			certificate_file = argv[++i];
		}
		else if(arg == "-r" || arg == "--pri-key") {
			pri_key_file = argv[++i];
		}
		else if(arg == "-b" || arg == "--pub-key") {
			pub_key_file = argv[++i];
		}
		else if(arg == "-n" || arg == "--no-input") {
			o_no_input = true;
		}
	}

	std::string input;
	if(!o_no_input)
		std::cin >> input;

	nDebug() << "input:" << input;

	mbedtls_x509_crt x509;
	mbedtls_x509_crt_init( &x509 );

	mbedtls_rsa_context *rsa = nullptr;

	if(!certificate_file.empty()) {
		int ret = mbedtls_x509_crt_parse_file (&x509, certificate_file.data());
		if(ret != 0) {
			nError() << "failed:  mbedtls_x509_crt_parse_file returned:" << ret;
			return -1;
		}
		nInfo() << "Certificate information ...";
		unsigned char buf[1024];
		ret = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ", &x509 );
		if( ret == -1 ) {
			nError() << "failed:  mbedtls_x509_crt_info returned:" << ret;
			return -1;
		}
		nInfo() << std::string((const char *)buf);
		rsa = mbedtls_pk_rsa(x509.pk);
		command = Command::ENCRYPT;
	}

	if(rsa == nullptr) {
		nError() << "unsufficient input";
		command = Command::HELP;
	}
	if(command == Command::HELP) {
		std::cout << "commands:\n"
					 "\t-c, --certificate: certificate file\n"
					 "\t-r, --pri-key: private key file\n";
		return 0;
	}

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init( &entropy );

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init( &ctr_drbg );

	if(command == Command::ENCRYPT && !input.empty()) {
		rsa->padding = MBEDTLS_RSA_PKCS_V21;
		rsa->hash_id = MBEDTLS_MD_SHA1;
		unsigned char buff[rsa->len];
		int ret = mbedtls_rsa_pkcs1_encrypt( rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, input.size(), (const unsigned char*)input.data(), buff );
		if( ret != 0 ) {
			nError() << "failed: mbedtls_rsa_pkcs1_encrypt returned:" << ret;
			return -1;
		}

		for(size_t i = 0; i < rsa->len; i++ )
			printf("%02X%s", buff[i], ( i + 1 ) % 16 == 0 ? "\n" : " " );
		nInfo() << "Done";
	}

	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	mbedtls_x509_crt_free(&x509);
	//mbedtls_rsa_free( rsa );

	return 0;
}
