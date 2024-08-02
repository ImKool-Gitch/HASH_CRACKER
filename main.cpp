#include <iostream>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <exception>
#include <chrono>

namespace Hash {
	std::string compute_md5(const std::string& data) {
		unsigned char digest[EVP_MAX_MD_SIZE];
		unsigned int length;
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
		EVP_DigestUpdate(ctx, data.c_str(), data.size());
		EVP_DigestFinal_ex(ctx, digest, &length);
		EVP_MD_CTX_free(ctx);

		std::stringstream buffer;
		for (unsigned i = 0; i < length; ++i)
			buffer << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(digest[i]);

		return buffer.str();
	}

	std::string compute_sha1(const std::string& data) {
		unsigned char digest[EVP_MAX_MD_SIZE];
		unsigned int length;
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
		EVP_DigestUpdate(ctx, data.c_str(), data.size());
		EVP_DigestFinal_ex(ctx, digest, &length);
		EVP_MD_CTX_free(ctx);

		std::stringstream buffer;
		for (unsigned i = 0; i < length; ++i)
			buffer << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(digest[i]);

		return buffer.str();
	}
}

int main(int argc, char** argv) {
	std::cout << "HASH CRACKER MADE BY ImKool-Gitch" << std::endl << std::endl;

	if (argc <= 1 || argc > 4) {
		std::cerr << "Enter the hash, a wordlist and then hash type!" << std::endl;
		std::cerr << "ex: program_name (hash here) (wordlist filename here) (hash type: md5, sha1)" << std::endl;
		return -1;
	}
	if (std::strcmp(argv[1], "help") == 0) {
		std::cout << "Hash types:\nmd5\nsha1" << std::endl;
		std::cout << "Program usage:\nprogram_name (hash here) (wordlist filename here) (hash type here)" << std::endl;
		return 0;
	}

	std::string single_word; // will hold the curent phrase to try
	std::string computed_hash;

	try {
		std::ifstream wordlist(argv[2]);
		wordlist.seekg(0, std::ios::beg);

		auto start = std::chrono::high_resolution_clock::now();

		while (std::getline(wordlist, single_word)) {
			if (!single_word.empty()) {
				if (std::strcmp(argv[3], "md5") == 0)
					computed_hash = Hash::compute_md5(single_word);
				else if (std::strcmp(argv[3], "sha1") == 0)
					computed_hash = Hash::compute_sha1(single_word);
				else
					throw std::runtime_error("invalid hash type !");

				std::cout << "Trying " << single_word << ' ' << argv[1] << ' ' << computed_hash << std::endl;
				
				if (computed_hash == argv[1]) {
					auto end = std::chrono::high_resolution_clock::now();
					std::cout << "Hash found: " << single_word << std::endl;
					auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
					std::cout << "In " << duration.count() << " milliseconds";
					break;
				}
			}

			single_word.clear();
		}
	}
	catch (const std::exception& err) {
		std::cerr << err.what() << std::endl;
		return -1;
	}

	return 0;
}
