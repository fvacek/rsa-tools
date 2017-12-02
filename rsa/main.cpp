#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

#include "necrolog.h"

#include <iostream>
#include <sstream>
#include <iomanip>

std::string unhex(const std::string &hex)
{
	std::string ret;
	for (size_t i = 0; i < hex.length(); i+=2) {
		auto digit_to_val = [](unsigned char c) -> unsigned char {
			c = tolower(c);
			return (c >= 'a')? c-'a'+10: c-'0';
		};
		unsigned char c = digit_to_val(hex[i]) * 16 + digit_to_val(hex[i+1]);
		ret.push_back(c);
	}
	return ret;
}

std::string hex(unsigned char c)
{
	auto val_to_digit = [](unsigned char c) {
		return (c >= 10)? c-10+'a': c+'0';
	};
	std::string ret;
	ret += val_to_digit(c/16);
	ret += val_to_digit(c%16);
	return ret;
}

std::string hex(const std::string &bytes)
{
	std::string ret;
	for(unsigned char c : bytes)
		ret += hex(c);
	return ret;
}

std::string dump_digest(const std::string &bytes)
{
	std::string ret;
	for (size_t i = 0; i < bytes.length(); ++i) {
		std::string s = hex(bytes[i]);
		ret += s + (( i + 1 ) % 16 == 0 ? "\n" : " ");
	}
	return ret;
}

/// multi precision integer to string
std::string mpi2str(const std::string &caption, mbedtls_mpi *n)
{
  size_t N = n->n * 8;
  char buff[N];
  mbedtls_mpi_write_binary(n, (unsigned char*)buff, N);
  std::string s(buff, N);
  return caption + " (" + std::to_string(n->n) + ") " + hex(s);
}

std::string dump_rsa (const std::string &title, mbedtls_rsa_context *rsa)
{
	std::string ret;
	ret += "============ RSA ==============\n";
	if(!title.empty()) {
		ret += title + '\n';
		ret += "-------------------------------\n";
	}
	ret += mpi2str("modulus          N:", &(rsa->N)) + '\n';
	ret += mpi2str("public exponent  E:", &(rsa->E)) + '\n';
	ret += mpi2str("private exponent D:", &(rsa->D)) + '\n';
	ret += mpi2str("1st prime factor P:", &(rsa->P)) + '\n';
	ret += mpi2str("2nd prime factor Q:", &(rsa->Q)) + '\n';
	ret += mpi2str("D % (P - 1)     DP:", &(rsa->DP)) + '\n';
	ret += mpi2str("D % (Q - 1)     DQ:", &(rsa->DQ)) + '\n';
	ret += mpi2str("1 / (Q % P)     QP:", &(rsa->QP)) + '\n';
	ret += "padding: " + std::to_string(rsa->padding) + '\n';
	ret += "hash: " + std::to_string(rsa->hash_id) + '\n';
	ret += "-------------------------------\n";
	return ret;
}

std::string dump_pk(const std::string &title, mbedtls_pk_context *pk)
{
	std::string ret;
	ret += "============= PK ==============\n";
	ret += title + '\n';
	ret += "-------------------------------\n";
	ret += "name: " + std::string(mbedtls_pk_get_name(pk)) + '\n';
	ret += "bit len: " + std::to_string(mbedtls_pk_get_bitlen(pk)) + '\n';
	ret += "len: " + std::to_string(mbedtls_pk_get_len(pk)) + '\n';
	ret += "can do RSA: " + std::string(mbedtls_pk_can_do(pk, MBEDTLS_PK_RSA)? "Y": "N") + '\n';
	if(mbedtls_pk_can_do(pk, MBEDTLS_PK_RSA))
		ret += dump_rsa("", mbedtls_pk_rsa(*pk));
	else
		ret += "-------------------------------\n";
	return ret;
}

template< typename T >
std::string int_to_hex( T i )
{
	std::stringstream stream;
	stream << "0x"
		   << std::setfill ('0') << std::setw(sizeof(T)*2)
		   << std::hex << i;
	return stream.str();
}

std::string error2string(int err_no)
{
	char buff[1024];
	mbedtls_strerror(err_no, buff, sizeof(buff));
	return "-" + int_to_hex(-err_no) + ": " + std::string(buff);
}

int main(int argc, char *argv[])
{
	enum class Command {UNKNOWN, ENCRYPT, DECRYPT, CHECK, HELP};
	Command command = Command::UNKNOWN;;
	mbedtls_pk_context *pri_pk = nullptr;
	mbedtls_pk_context *pub_pk = nullptr;
	std::string pub_key_file;
	std::string pri_key_file;
	std::string pri_key_password;
	std::string certificate_file;
	bool o_no_input = false;
	bool o_ihex = false;
	bool o_ohex = false;
	for (int i = 1; i < argc; ++i) {
		std::string arg(argv[i]);
		if(arg == "-h" || arg == "--help")
			command = Command::HELP;
		else if(arg == "-c" || arg == "--certificate") {
			certificate_file = argv[++i];
		}
		else if(arg == "-r" || arg == "--pri-key") {
			pri_key_file = argv[++i];
		}
		else if(arg == "-p" || arg == "--pri-key-password") {
			pri_key_password = argv[++i];
		}
		else if(arg == "-b" || arg == "--pub-key") {
			pub_key_file = argv[++i];
		}
		else if(arg == "-n" || arg == "--no-input") {
			o_no_input = true;
		}
		else if(arg == "--ihex") {
			o_ihex = true;
		}
		else if(arg == "--ohex") {
			o_ohex = true;
		}
		else if(arg == "--hex") {
			o_ihex = true;
			o_ohex = true;
		}
		else {
			nError() << "Unknown CLI parameter:" << arg;
		}
	}

	if(o_ihex)
		nDebug() << "Expecting HEX input";
	else
		nDebug() << "Expecting BIN input";
	if(o_ohex)
		nDebug() << "Generating HEX output";
	else
		nDebug() << "Generating BIN output";

	std::string input;// = "ahoj babi";
	if(!o_no_input) {
		while(true) {
			int c = std::cin.get();
			if(c < 0)
				break;
			input.push_back((char)c);
		}
		nDebug() << "input:" << input << hex(input);
		if(o_ihex) {
			input = unhex(input);
		}
	}

	mbedtls_x509_crt x509;
	mbedtls_x509_crt_init( &x509 );

	mbedtls_pk_context pk_pub_ctx;
	mbedtls_pk_init(&pk_pub_ctx);

	mbedtls_pk_context pk_pri_ctx;
	mbedtls_pk_init(&pk_pri_ctx);

	if(!certificate_file.empty()) {
		int ret = mbedtls_x509_crt_parse_file (&x509, certificate_file.data());
		if(ret != 0) {
			nError() << "failed:  mbedtls_x509_crt_parse_file returned:" << error2string(ret);
			return -1;
		}
		nDebug() << "Certificate information ...";
		unsigned char buf[1024];
		ret = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ", &x509 );
		if( ret == -1 ) {
			nError() << "failed:  mbedtls_x509_crt_info returned:" << error2string(ret);
			return -1;
		}
		nDebug() << std::string((const char *)buf);
		pub_pk = &x509.pk;
		nDebug() << "Public key loaded:\n" << dump_pk(certificate_file, pub_pk);
	}
	if(!pub_key_file.empty()) {
		int ret = mbedtls_pk_parse_public_keyfile(&pk_pub_ctx, pub_key_file.data());
		if(ret != 0) {
			nError() << "failed:  mbedtls_pk_parse_public_keyfile:" << pub_key_file << "returned:" << error2string(ret);
			return -1;
		}
		pub_pk = &pk_pub_ctx;
		nDebug() << "Public key loaded:\n" << dump_pk(pub_key_file, pub_pk);
	}
	if(!pri_key_file.empty()) {
		int ret = mbedtls_pk_parse_keyfile(&pk_pri_ctx, pri_key_file.data(), pri_key_password.data());
		if(ret != 0) {
			nError() << "failed:  mbedtls_pk_parse_keyfile:" << pri_key_file << "returned:" << error2string(ret);
			return -1;
		}
		pri_pk = &pk_pri_ctx;
		nDebug() << "Private key loaded:\n" << dump_pk(pri_key_file, pri_pk);
	}

	if(command == Command::UNKNOWN) {
		if(pub_pk && pri_pk) {
			command = Command::CHECK;
		}
		else if(pub_pk) {
			command = Command::ENCRYPT;
		}
		else if(pri_pk) {
			command = Command::DECRYPT;
		}
		else {
			nError() << "unsufficient input";
			command = Command::HELP;
		}
	}

	if(command == Command::HELP) {
		std::cout << "commands:\n"
					 "\t-h, --help: this help\n"
					 "\t-c, --certificate: certificate file\n"
					 "\t-b, --pub-key: public key file\n"
					 "\t-r, --pri-key: private key file\n"
					 "\t-p, --pri-key-password: private key password\n"
					 "\t--ihex, --ohex, --hex: input, otput, both is in HEX text format\n"
					 ;
		return 0;
	}

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init( &entropy );

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init( &ctr_drbg );

	const unsigned char pers[] = "eyas_rsa_oaep_encrypt_voe";

	if(pub_pk && pri_pk) {
		/// check keys
		int ret = mbedtls_pk_check_pair(pub_pk, pri_pk);
		if( ret != 0 ) {
			nError() << "failed: mbedtls_pk_check_pair returned:" << error2string(ret);
			return -1;
		}
		nInfo() << "Key pair check OK";
	}
	else if(command == Command::ENCRYPT && !input.empty() && pub_pk) {
		mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pub_pk);
		rsa->padding = MBEDTLS_RSA_PKCS_V21;
		rsa->hash_id = MBEDTLS_MD_SHA1;
		unsigned char buff[rsa->len];
		{
			nDebug() << "Seeding the random number generator...";
			int ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, pers, sizeof( pers ) );
			if( ret != 0 ) {
				nError() << "failed: mbedtls_ctr_drbg_seed returned:" << error2string(ret);
				return -1;
			}
		}
		{
			int ret = mbedtls_rsa_pkcs1_encrypt( rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, input.size(), (const unsigned char*)input.data(), buff );
			if( ret != 0 ) {
				nError() << "failed: mbedtls_rsa_pkcs1_encrypt returned:" << error2string(ret);
				return -1;
			}
		}
		//for(size_t i = 0; i < rsa->len; i++ )
		//	fprintf(stderr, "%02X%s", buff[i], ( i + 1 ) % 16 == 0 ? "\n" : " " );
		std::string digest(buff, buff + rsa->len);
		nDebug().nospace() << "Digest:\n" << dump_digest(digest);
		if(o_ohex)
			std::cout << hex(digest);
		else
			std::cout << digest;
		nDebug() << "Done" << (o_ohex? "HEX": "BIN") << " output generated";
	}
	else if(command == Command::DECRYPT && !input.empty() && pri_pk) {
		mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pri_pk);
		rsa->padding = MBEDTLS_RSA_PKCS_V21;
		rsa->hash_id = MBEDTLS_MD_SHA1;
		unsigned char buff[rsa->len];
		std::string digest;
		{
			nDebug() << "Seeding the random number generator...";
			int ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, pers, sizeof( pers ) );
			if( ret != 0 ) {
				nError() << "failed: mbedtls_ctr_drbg_seed returned:" << error2string(ret);
				return -1;
			}
		}
		{
			size_t olen;
			int ret = mbedtls_rsa_pkcs1_decrypt( rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC
												 , &olen
												 , (const unsigned char*)input.data()
												 , buff, sizeof(buff) );
			if( ret != 0 ) {
				nError() << "failed: mbedtls_rsa_pkcs1_decrypt returned:" << error2string(ret);
				return -1;
			}
			digest = std::string(buff, buff + olen);
		}
		nDebug() << "Decrypted:" << digest;
		nDebug() << "hex:" << hex(digest);
		if(o_ohex)
			std::cout << hex(digest);
		else
			std::cout << digest;
	}

	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	mbedtls_x509_crt_free(&x509);
	mbedtls_pk_free(&pk_pub_ctx);
	mbedtls_pk_free(&pk_pri_ctx);

	return 0;
}
