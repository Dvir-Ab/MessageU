#include <cstdlib>
#include <stdint.h>
#include <modes.h>

#include <iomanip>
#include <algorithm>

#include <hex.h>
#include <aes.h>
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>

#include <string>
#include <fstream>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>

#define MAX_LEN 1024

bool is_little_endian() {
	int i = 1;
	return (uint8_t)i == 1;
}

void reverseIfBigEndian(std::string& str) {
	if (!is_little_endian())
		std::reverse(str.begin(), str.end());
}

/** 
*	init the boost trivia logger 
*/
void init_log(){
	boost::log::register_simple_formatter_factory<boost::log::trivial::severity_level, char>("Severity");

	boost::log::add_file_log(
		boost::log::keywords::open_mode = std::ios::app, //append to the last log file, if yet to rotate
		boost::log::keywords::file_name = "client_%N.log", // templete for the log file name
		boost::log::keywords::rotation_size = 10 * MAX_LEN * MAX_LEN, // max size til rotation
		boost::log::keywords::time_based_rotation = boost::log::sinks::file::rotation_at_time_point(0, 0, 0), // rotate file at midnight
		boost::log::keywords::format = "[%TimeStamp%] [%Severity%] %Message%", // formate of the log output
		boost::log::keywords::auto_flush = true // flush after each log
	);

	boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::info);

	boost::log::add_common_attributes();
}

/**
*	log messages
*		
*/
void log_stuff(const std::string& str, bool toCout=false) {
	if (str.empty()) return;
	if (toCout) std::cout << str << std::endl;
	BOOST_LOG_TRIVIAL(info) << str;
}

#include <exception>
#include <boost/filesystem/operations.hpp>

class ExceptionLogger : public std::exception {
public:
	explicit ExceptionLogger() :exception() {};
	explicit ExceptionLogger(const std::string& s) : std::exception(s.c_str()) { BOOST_LOG_TRIVIAL(error) << s; };
	explicit ExceptionLogger(const std::exception& e) : std::exception(e) { BOOST_LOG_TRIVIAL(error) << e.what(); };
	explicit ExceptionLogger(const char* msg) : std::exception(msg) { BOOST_LOG_TRIVIAL(error) << std::string(msg); };
};

class ConnectionException : public ExceptionLogger {};

#define RSA_SIZE 160
#define AES_SIZE 16
#define MAX_NAME_LEN 255


class MyCipher {
private:
	const char* PR_NAME = "me.pr", * PU_NAME = "me.pub";
	void Load(const std::string& filename, CryptoPP::BufferedTransformation& bt) {
		CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::Base64Decoder);
		file.TransferTo(bt);
		bt.MessageEnd();
	};
public:
	MyCipher() {};
	void init(std::string filename) {
		if (!boost::filesystem::exists(filename + ".prv")) {
			CryptoPP::AutoSeededRandomPool rng;
			CryptoPP::InvertibleRSAFunction privkey;
			privkey.Initialize(rng, MAX_LEN);

			// With the current version of Crypto++, MessageEnd() needs to be called
			// explicitly because Base64Encoder doesn't flush its buffer on destruction.
			CryptoPP::Base64Encoder privkeysink(new CryptoPP::FileSink((filename + ".prv").c_str()));
			privkey.DEREncode(privkeysink);
			privkeysink.MessageEnd();

			// store the public key separately, because we will be sending the public key to a third party.
			CryptoPP::RSAFunction pubkey(privkey);

			CryptoPP::Base64Encoder pubkeysink(new CryptoPP::FileSink((filename + ".pub").c_str()));
			pubkey.DEREncode(pubkeysink);
			pubkeysink.MessageEnd();
		}
	}

	std::string decryptKey(std::string pk, std::string data) {
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::ByteQueue bytes;
		CryptoPP::FileSource file("me.prv", true, new CryptoPP::Base64Decoder);
		file.TransferTo(bytes);
		bytes.MessageEnd();
		CryptoPP::RSA::PrivateKey privateKey;
		privateKey.Load(bytes);

		// decrypt
		std::string decrypted;
		CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);
		CryptoPP::StringSource ss(data, true, new CryptoPP::PK_DecryptorFilter(rng, d, new CryptoPP::StringSink(decrypted)));
		return decrypted;
	}

	std::string decryptData(std::string symmericKey, const std::string& data) {
		// cbc decryptor
		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
		memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE); // init iv
		CryptoPP::AES::Decryption aesDec(reinterpret_cast<const unsigned char*>(symmericKey.c_str()), CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDec, iv);

		std::string cipherData;
		CryptoPP::StreamTransformationFilter encryptor(cbcDecryption, new CryptoPP::StringSink(cipherData), CryptoPP::StreamTransformationFilter::NO_PADDING);
		encryptor.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
		encryptor.MessageEnd();
		return cipherData;
	}

	std::string encrypt_sym_with_pub(std::string symmericKey, std::string key) {
		CryptoPP::AutoSeededRandomPool rng;

		//Read public key
		CryptoPP::ByteQueue bytes;
		CryptoPP::StringSource str((CryptoPP::byte*)key.c_str(),key.size(), true);
		str.TransferTo(bytes);
		bytes.MessageEnd();
		CryptoPP::RSA::PublicKey pubKey;
		pubKey.Load(bytes);


		// Save the key to an unsigned char buffer.
		// Note on key size: We use 160 character here becuase our key is 1024 bits in size (the actual public key contains more data then just "the key")
		// In a real world scenario we would have used different key sizes and thus, using a dynamic buffer (vector, or even an std::string)
		static const size_t KEYSIZE = 160;
		CryptoPP::byte buf[KEYSIZE];
		CryptoPP::ArraySink as(buf, KEYSIZE);
		pubKey.Save(as);


		// copy the buffer to a different variable
		CryptoPP::byte buf2[KEYSIZE];
		memcpy(buf2, buf, KEYSIZE);
		CryptoPP::ArraySource as2(buf2, KEYSIZE, true);

		CryptoPP::RSA::PublicKey pubKey2;
		pubKey2.Load(as2);


		// encrypt (using public key)
		std::string ciphertext;
		CryptoPP::RSAES_OAEP_SHA_Encryptor e(pubKey2);
		CryptoPP::StringSource ss(symmericKey, true, new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(ciphertext)));
		return ciphertext;
	}

	std::string encrypt_with_sym(std::string symmericKey, const std::string& data) {
		// cbc encryptor
		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };
		CryptoPP::AES::Encryption aesEnc((CryptoPP::byte*)symmericKey.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEnc, iv);

		std::string cipherData;
		CryptoPP::StreamTransformationFilter encryptor(cbcEncryption, new CryptoPP::StringSink(cipherData));
		encryptor.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
		encryptor.MessageEnd(); // flush the ciphered data to std::string
		return cipherData;
	}

	std::string new_sym_key() {
		CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::AutoSeededRandomPool asrp;
		asrp.GenerateBlock(key, key.size());
		return std::string((const char*)key.data(), key.size());
	}
};

#include <type_traits>

template <typename T, class = typename std::enable_if_t<std::is_unsigned_v<T>>::type>
inline T fromCharPt(const char* chrPt, bool isBigEndian = false) {
	T res, mask = 0xFF;
	const T size = sizeof(T), step = 8;
	const bool toReverse = isBigEndian == is_little_endian(); // this machine is little XNOR the request is big endian
	for (int j, i = 0; i < size && chrPt; i++, mask = mask << step) {
		j = isBigEndian ? size - i - 1 : i;
		res = res | (((CryptoPP::byte)chrPt[j] << (step * i)) & mask);
	}
	return res;
}

unsigned short chrArr_to_ushort(const char* arr, bool isBigEndian = false) {
	if (std::strlen(arr) != sizeof(unsigned short)) {
		throw std::length_error("error: trying to change, \'%s\' , to short.");
	}
	if (isBigEndian) {
		return (((CryptoPP::byte)arr[0]) << 8) | (CryptoPP::byte)arr[1];
	}
	return  (((CryptoPP::byte)arr[1]) << 8) | (CryptoPP::byte)arr[0];
}
unsigned int net_uchr_to_uint_host(const char* chrp, bool isBigEndian = false) {
	if (!chrp) { return NULL; }
	unsigned int c, res = 0, mask = 0xFF;
	const size_t len = sizeof(unsigned int);
	int j;
	for (int i = 0; i < len && chrp; i++){//,mask = mask << len) {
		j = isBigEndian ? len - i - 1 : i;
		res = res | (((c = ((CryptoPP::byte)chrp[j])) & mask) << (2 * len * i));
	}
	return res;
}

std::string store_ushort(unsigned short us, bool isBigEndian = false) {
	const unsigned short m = (unsigned short)0xFF;
	std::string res = "";
	if (isBigEndian) {
		res.push_back(us >> 8);
		res.push_back((char)us);
	}
	else {
		res.push_back(us);
		res.push_back(us >> 8);
	}
	return res;
}

std::string store_uint(unsigned int ui, bool isBigEndian = false) {
	std::string res = "";
	for (size_t i = 0; i < sizeof(ui); i++)
		res.push_back(ui >> 8 * i);
	if (isBigEndian == is_little_endian()) 
		std::reverse(res.begin(), res.end());
		/*{
		res += store_ushort(ui >> 8, isBigEndian) + store_ushort((unsigned short)ui, isBigEndian);
	}
	else {
		res += store_ushort((unsigned short)ui, false) + store_ushort(ui >> 8, false);
	}*/
	return res;
}

typedef struct UserId {
public:
	UserId() {  }
	UserId(std::string data) { this->setData(data); }

	bool operator==(const UserId& userid) {
		for (int i = 0; i < AES_SIZE; i++) {
			if (this->uid[i] != userid.uid[i])
				return false;
		}
		return true;
	}
	UserId& operator= (const UserId& userid) {
		if (this == &userid) {
			return *this;
		}
		std::copy(userid.uid, userid.uid + AES_SIZE, this->uid);
		return *this;
	}
	std::string data(bool isBigEndian=false) {
		std::string res((char*)this->uid, AES_SIZE);
		if (isBigEndian) 
			std::reverse(res.begin(), res.end());
		return res;
	}
	/*set the uid data
		may throw exception if the length of data != AES_SIZE*/
	void setData(std::string data) {
		if (data.size() != AES_SIZE)
			throw ExceptionLogger(("Error: recieved uid of length " + std::to_string(data.size()) + " .").c_str());
		for (size_t i = 0; i < AES_SIZE; i++) {
			this->uid[i] = data[i];
		}
	}

	bool operator ()(const UserId& luid, const UserId& ruid) const{
		return std::string((char*)luid.uid, AES_SIZE) < std::string((char*)ruid.uid, AES_SIZE);
	}
private:
	bool hasNone = false;
	uint8_t uid[AES_SIZE] = { 0 };
};

const UserId NoneUID;

namespace ClientCodes {
	enum {
		SYM_REQ = 1, SEND_SYM, TXT_MSG, FILE_MSG,
		REGISTRETION = 100, USERLIST, GETPUB, SENDMSG,PULL_MSG,
		REGISTRATION_RESULT = 1000, USRS_LST_RTN, PUB_REQ, MSG_RECEIVED, PULLED_MSGS,
		GNRL_ERR = 9000
	};
};

class SimpleHeader {
public:
	SimpleHeader(uint8_t ver, uint32_t payloadSize, std::string pld) : 
		_version(ver), _pld_size(payloadSize) , _pld(pld) {
		if (pld.empty()) { this->_pld_size = 0; }
		else if (payloadSize == 0) { this->_pld.clear(); }
	};
	std::string data(bool isBigEndian) { std::cout << "simple" << std::endl; return (char)this->_version + store_uint(this->_pld_size) + this->_pld; };
protected:
	uint8_t _version;
	uint32_t _pld_size;
	std::string _pld;
};

class ResponseHeader : public SimpleHeader {
public:
	ResponseHeader(uint8_t ver, uint16_t code, uint32_t payloadSize, std::string pld) : _code(code), SimpleHeader(ver, payloadSize, pld) {}

	std::string data(bool isBigEndian) {
		std::string res = "";
		res.push_back(this->_version);
		res.push_back(this->_code);
		res += store_uint(this->_pld_size);
		if (this->_pld_size != 0) res += this->_pld;
		return  res;
	}
protected:
	uint16_t _code;
};

class RequastHeader : public ResponseHeader {
public:
	RequastHeader(UserId usrId, const uint8_t code, uint32_t payloadSize,std::string pld="",uint8_t ver = 2, bool isIndependent=false)
		: _usrId(usrId), _isIndependent(isIndependent), ResponseHeader(ver, code, payloadSize,pld) {}

	std::string data(bool isBigEndian=false) {
		std::string res = ResponseHeader::data(isBigEndian);
		if (res.empty()) { throw ExceptionLogger("some thing went wrong with header data!"); }
		if (this->_isIndependent) { res = res.substr(1, res.size() - 1); }
		return this->_usrId.data(isBigEndian) + res;
	}
protected:
	bool _isIndependent;
	UserId _usrId;
};

class MessageHeader : public RequastHeader {
public:
	MessageHeader(UserId usrId, uint8_t code, uint32_t payloadSize, std::string pld)
		: RequastHeader(usrId, code, payloadSize, pld, 2, true) {}
	std::string data(bool isBigEndian=false) { return RequastHeader::data(isBigEndian); }
};




class Friend {
private:
	std::string _name, _pub, _sym;
	UserId _fuid;
public:
	Friend(std::string user_name = "", UserId user_id = NoneUID, std::string sym_key = "", std::string pub_key = "") :
		_sym(sym_key), _fuid(user_id), _pub(std::string(pub_key)) {
		if(!user_name.empty()) this->setName(user_name);
	}

	Friend(const Friend& f) {
		this->_fuid = f._fuid;
		this->_name = f._name;
		this->_pub = f._pub;
		this->_sym = f._sym;
	}

	bool havePubKey() { return this->_pub.size() == RSA_SIZE; }

	bool operator==(const Friend& f) {
		return (this->_name == f._name) && (this->_fuid == f._fuid);
	}
	std::string getName() { return this->_name; }

	UserId getUid() { return this->_fuid; }

	std::string getPub() { return this->_pub; }

	std::string getSym() { return this->_sym; }

	void setName(std::string name) {
		if (name.empty()) return;
		this->_name = std::string(name);
		this->_name.erase(std::find(this->_name.begin(), this->_name.end(), '\0'), this->_name.end());
	}

	void setUid(UserId uid) { this->_fuid = uid; }

	void setPub(std::string pubstr) { if (!pubstr.empty()) this->_pub = std::string(pubstr); }

	void setSym(std::string symstr) { if (!symstr.empty()) this->_sym = std::string(symstr); }

	Friend& operator=(const Friend& f) {
		if (this == &f) { //not self assigned
			return *this;
		}
		this->_name = std::string(f._name);
		this->_fuid = f._fuid;
		this->_sym = std::string(f._sym);
		this->_pub = std::string(f._pub);
		return *this;
	}
};

class FriendsManager {
public:
	FriendsManager() : _myself() {}

	Friend getSelf() {
		Friend f = this->_myself;
		return f;
	}
	void setSelf(const Friend& f) {
		this->_myself = f;
		this->_isSelfInit = true;
	}

	Friend getFriend(std::string name) { 
		if (this->_frndsMap.find(name) == this->_frndsMap.end()) throw ExceptionLogger(("The friend with the name: \'" + name + "\', dosn\'t exist.").c_str());
		return Friend(this->_frndsMap[name]);
	}

	bool isInit() { return this->_isSelfInit; }

	void setFriend(std::string name,Friend f) {
		this->_frndsMap[name] = f;
		this->_idsMap[f.getUid()] = name;
	}

	bool exist(std::string user="") {
		if (user.empty()) {
			return _myself.getName().empty();
		}
		return this->_frndsMap.find(user) != this->_frndsMap.end();
	}

	Friend getFriendName(UserId uid) {
		if(this->_idsMap.find(uid) == this->_idsMap.end())
			throw ExceptionLogger("Failed to find a friend by uid!");
		std::string name = this->_idsMap[uid];
		return this->getFriend(name);
	}
private:
	bool _isSelfInit = false;
	Friend _myself;
	std::map<std::string, Friend> _frndsMap;
	std::map<UserId, std::string,UserId> _idsMap;
};

