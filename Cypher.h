
#include <rsa.h>
#include <files.h>
#include <modes.h>
#include <hex.h>
#include <aes.h>
#include <iomanip>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/endian.hpp>
#include "utils.h"

#define RSE_SIZE 128
//#define AES_SIZE 16

class MyCipher {
private:
	enum { AES_SIZE = 16, SYM_SIZE = 128 };
	const char* PR_NAME = "me.pr", * PU_NAME = "me.pub";
	CryptoPP::RSAFunction* _pub_key;
	void Load(const std::string& filename, CryptoPP::BufferedTransformation& bt) {
		CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::HexDecoder);
		file.TransferTo(bt);
		bt.MessageEnd();
	};


public:
	static MyCipher& getCipher(std::string filename);

	void init(std::string filename);
	//~MyCipher() {}


	CryptoPP::byte* decrypt(const std::string& filename, const std::string& data);
	std::string encrypt_sym_with_pub(CryptoPP::byte* symmericKey, std::string pubKey);
	std::string encrypt_with_sym(CryptoPP::byte* symmericKey, const std::string& data);
	//std::string prepare(const std::string& fileName, const std::string& data);
	CryptoPP::byte* new_sym_key();
};