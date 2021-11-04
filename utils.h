#include <cstdlib>
#include <stdint.h>
#include <osrng.h>
#include <rsa.h>
#include <files.h>
#include <modes.h>
#include <hex.h>
#include <aes.h>
#include <iomanip>


/*----------------------------------------------------------
*	print the string, str, to ostrm in hex				  *
*														  *
*  ostrm - stream for printing							  *
*  str - string to print as hex							  *
----------------------------------------------------------*/
void printStrAsHex(std::ostream& ostrm, std::string str) 
{
	for (auto c : str)
		ostrm << std::hex <<  unsigned((unsigned char)c);
	ostrm << std::endl;
}


/*----------------------------------------------------------
*	convert the char array, arr, to unsigned short.		  *
*														  *
*	arr - char array to convert to unsigned short,		  *
*		  the length of str must be equal to the size of  *
*		  unsigned short, else length_error will be raise *
* 														  *
* 	isBigEndian - trit arr as big endian if it's else as  *
*				  little endian							  *
----------------------------------------------------------*/
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
	const int len = sizeof(unsigned int);
	int j;
	for (int i = 0; i < len && chrp; i++, mask = mask << len) {
		j = isBigEndian ? len - i - 1 : i;
		res = res | ((c = ((CryptoPP::byte)chrp[j]) << (len * i)) & mask);
	}
	return res;
}

std::string store_ushort(unsigned short us, bool isBigEndian = false) {
	const unsigned short m = (unsigned short)0xFF;
	std::string res = "";
	if (isBigEndian) {
		res.push_back(us >> 8);
		res.push_back(us);
	}
	else {
		res.push_back(us);
		res.push_back(us >> 8);
	}
	return res;
}

std::string store_uint(unsigned int ui, bool isBigEndian = false) {
	std::string res = "";
	if (isBigEndian) {
		res += store_ushort(ui >> 8, isBigEndian) + store_ushort((unsigned short)ui, isBigEndian);
	}
	else {
		res += store_ushort((unsigned short)ui, false) + store_ushort(ui >> 8, false);
	}
	return res;
}

typedef struct UserId {
public:
	~UserId() { delete[] this->uid; }

	enum { size = 16};
	bool operator==(const UserId& userid) {
		for (int i = 0; i < this->size; i++) {
			if (this->uid[i] != userid.uid[i])
				return false;
		}
		return true;
	}
	UserId& operator= (const UserId& userid) {
		if (this == &userid) {
			return *this;
		}
		std::copy(userid.uid, userid.uid + size - 1, this->uid);
		return *this;
	}
	std::string data(bool isBigEndian) {
		std::string res((char*)this->uid,this->size);
		if (!isBigEndian) 
			std::reverse(res.begin(), res.end());
		return res;
	}

	void setData(std::string data) {
		if (data.size() != this->size)
			return;
		/*for (size_t i = 0; i < this->size; i++) {
			this->uid[i] = (uint8_t)data[i];
		}*/
		std::memcpy(this->uid, data.c_str(), this->size);
	}
private:
	//bool hasNone = false;
	uint8_t uid[size] = { 0 };
};

const UserId NoneUID;

class SimpleHeader {
public:
	SimpleHeader(uint8_t ver, uint32_t payloadSize, std::string pld) : 
		_version(ver), _pld_size(payloadSize) , _pld(pld) {
		if (pld.empty()) { this->_pld_size = 0; }
		else if (payloadSize == 0) { this->_pld.clear(); }
	};
	std::string data(bool isBigEndian) { return (char)this->_version + store_uint(this->_pld_size) + this->_pld; };
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
		return res + store_uint(this->_pld_size) + this->_pld;
	}
protected:
	uint16_t _code;
};

class RequastHeader : public ResponseHeader {
public:
	RequastHeader(UserId usrId, const uint8_t code, uint32_t payloadSize,std::string pld="",uint8_t ver = 2, bool isIndependent=false)
		: _usrId(usrId), _isIndependent(isIndependent), ResponseHeader(ver, code, payloadSize,pld) {}

	std::string data(bool isBigEndian=false) {
		std::string res = "", superRes = ResponseHeader::data(isBigEndian);
		if (superRes.empty()) { throw std::exception("some thing went wrong with header data!"); }
		if (this->_isIndependent) { res = superRes.substr(1, superRes.size() - 1); }
		else { res = superRes; }
	/*	std::string res = this->_usrId.data(isBigEndian);
		if (!this->_isIndependent) { res.push_back(this->_version); }
		if (!isBigEndian) this->_pld.reserve();*/
		return this->_usrId.data(isBigEndian) + res;//+ (char)this->_code + store_uint(this->_pld_size) + this->_pld;
	}
protected:
	bool _isIndependent;
	UserId _usrId;
};

class MessageHeader : public RequastHeader {
public:
	MessageHeader(UserId usrId, uint8_t code, uint32_t payloadSize, std::string pld)
		: RequastHeader(usrId, code, payloadSize, pld, true) {}
	std::string data(bool isBigEndian=false) { return RequastHeader::data(isBigEndian); }
};




class Friend {
private:
	std::string _name;
	UserId _fuid;
	CryptoPP::byte* _sym; //doto: change the type to vector or string
	std::string _pub;
	//friend class RequestHandler;
	enum { PUB_KEY_SIZE = 256 };
public:
	Friend(std::string user_name = "", UserId user_id = NoneUID, CryptoPP::byte* sym_key = nullptr, std::string pub_key = "") :
		_sym(sym_key), _name(std::string(user_name)), _fuid(user_id), _pub(std::string(pub_key)) {}

	Friend(const Friend& f) { *this = f; }

	bool havePubKey() { return this->_pub.size() == PUB_KEY_SIZE; }

	bool operator==(Friend& f) {
		return (this->_name == f._name) && (this->_fuid == f._fuid);
	}
	std::string getName() { return this->_name; }

	UserId getUid() { return this->_fuid; }

	std::string getPub() { return this->_pub; }

	CryptoPP::byte* getSym() { return this->_sym; }

	void setName(std::string name) { this->_name = std::string(name); }

	void setUid(UserId uid) { this->_fuid = uid; }

	void setPub(std::string pubstr) { if (!pubstr.empty()) this->_pub = std::string(pubstr); }

	void setSym(std::string symstr) { if (!symstr.empty()) this->_sym = (CryptoPP::byte*)symstr.c_str(); }

	Friend& operator=(const Friend& f) {
		if (this == &f) { //not self assigned
			return *this;
		}
		this->_name = std::string(f._name);
		this->_fuid = f._fuid;
		this->_sym = f._sym;
		this->_pub = std::string(f._pub);
		return *this;
	}
};

class FriendsManager : private std::map<std::string, Friend> {
public:
	FriendsManager() : _myself(), std::map<std::string, Friend>() {}

	Friend getSelf() {
		const std::lock_guard<std::mutex> lock(this->_slf_mtx);
		Friend f = this->_myself;
		return f;
		// mutex will be unlocked (from lock destructor) when leaving the scope of lock
	}
	void setSelf(const Friend& f) {
		const std::lock_guard<std::mutex> lock(this->_slf_mtx);
		this->_myself = f;
	}

	Friend * getFriend(std::string name) { 
		const std::lock_guard<std::mutex> lock(this->_otr_mtx);
		if (this->find(name) == this->end()) return nullptr;
		Friend f(this->operator[](name));
		return &f;
	}

	void setFriend(std::string name,const Friend f) {
		const std::lock_guard<std::mutex> lock(this->_otr_mtx);
		(*this)[name] = f;
	}

	bool exist(std::string user="") {
		if (user.empty()) {
			const std::lock_guard<std::mutex> lock(this->_slf_mtx);
			return _myself.getName().empty();
		}
		const std::lock_guard<std::mutex> lock(this->_otr_mtx);
		return this->find(user) == this->end();
	}
private:
	Friend _myself;
	std::mutex _slf_mtx, _otr_mtx;
};

#define RSE_SIZE 128
#define AES_SIZE 16

class MyCipher {
private:
	enum { SYM_SIZE = 128 };
	const char* PR_NAME = "me.pr", * PU_NAME = "me.pub";
	CryptoPP::RSAFunction* _pub_key;
	void Load(const std::string& filename, CryptoPP::BufferedTransformation& bt) {
		CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::HexDecoder);
		file.TransferTo(bt);
		bt.MessageEnd();
	};

	static MyCipher _cipher;

public:
	static MyCipher& getCipher(std::string filename)
	{
		_cipher.init(filename);
		return _cipher;
	}

	void init(std::string filename) {
		if (!boost::filesystem::exists(filename+".prv")) {
			CryptoPP::AutoSeededRandomPool asrp;
			CryptoPP::InvertibleRSAFunction priv_key;
			priv_key.Initialize(asrp, 1024);
			CryptoPP::HexEncoder priv_key_sink(new CryptoPP::FileSink((filename + ".prv").c_str()));

			priv_key.DEREncode(priv_key_sink);
			priv_key_sink.MessageEnd(); // call MessageEnd() to be called flush the buffer

			_pub_key = new CryptoPP::RSAFunction(priv_key);

			CryptoPP::HexEncoder pub_key_sink(new CryptoPP::FileSink((filename + ".pub").c_str()));
			_pub_key->DEREncode(pub_key_sink);
			pub_key_sink.MessageEnd();
		}
		else if (!boost::filesystem::exists(filename + ".pub")) {
			//error
			throw std::exception("Missing user's data files");
		}

	}
	//~MyCipher() {}


	CryptoPP::byte* decrypt(const std::string& filename, const std::string& data) {
		try {
			CryptoPP::ByteQueue bq;
			CryptoPP::SecByteBlock ciperData(data.size());
			this->Load(filename, bq);
			CryptoPP::RandomNumberGenerator rnd;
			CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor;
			decryptor.AccessKey().Load(bq);
			decryptor.Decrypt(rnd, (CryptoPP::byte*)data.c_str(), data.size(), (CryptoPP::byte*)ciperData, decryptor.AccessKey());
			return ciperData.data();
		}
		catch (std::exception& e) {
			//log this exception
			throw std::exception(e);
		}
	};

	std::string encrypt_sym_with_pub(CryptoPP::byte* symmericKey, std::string pubKey) {
		CryptoPP::RandomNumberGenerator rng;
		CryptoPP::ByteQueue bq;
		CryptoPP::SecByteBlock cipherData;
		std::string cipherTxt;
		bq.Put(symmericKey, SYM_SIZE);
		bq.MessageEnd();
		CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor;
		encryptor.AccessKey().Load(bq);
		encryptor.Encrypt(rng, symmericKey, SYM_SIZE, cipherData);
		return std::string(cipherData.begin(), cipherData.end());
	}

	std::string encrypt_with_sym(CryptoPP::byte* symmericKey, const std::string& data) {
		// cbc encryptor
		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };
		CryptoPP::AES::Encryption aesEnc(symmericKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEnc, iv);

		std::string cipherData;
		CryptoPP::StreamTransformationFilter encryptor(cbcEncryption, new CryptoPP::StringSink(cipherData));
		encryptor.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
		encryptor.MessageEnd(); // flush the ciphered data to std::string
		return cipherData;
	}

	std::string prepare(const std::string& fileName, const std::string& data) {
		//create an aes key
		CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };
		CryptoPP::AutoSeededRandomPool asrp;
		asrp.GenerateBlock(key, sizeof(key));
		//asrp.GenerateBlock(iv, sizeof(iv));
		std::string cipher, to_prepare_c(data);
		try {
			// cbc encryptor
			CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption enc;
			enc.SetKeyWithIV(key, sizeof(key), iv);

			// remove padding
			CryptoPP::StringSource s(to_prepare_c, true,
				new CryptoPP::StreamTransformationFilter(enc,
					new CryptoPP::StringSink(cipher)
				)
			);

			CryptoPP::StreamTransformationFilter filter(enc);
			filter.Put((const CryptoPP::byte*)to_prepare_c.data(), to_prepare_c.size());
			filter.MessageEnd();

			//CryptoPP::AutoSeededRandomPool asrp;
			//		CryptoPP::InvertibleRSAFunction priv_key;
			CryptoPP::ByteQueue bq;
			this->Load(fileName, bq);
			//	priv_key.Load(bq);//FileSource(this->PR_NAME,true,new CryptoPP::Base64Decoder()));

			CryptoPP::RSAFunction pub_key;
			bq.Clear();
			std::string in_buff;
			CryptoPP::FileSource file("me.info", true);
			std::istream* in = file.GetStream();
			std::getline(*in, in_buff, '\n');
			in_buff.clear();
			std::getline(*in, in_buff, '\n');
			pub_key.Load(bq);
		}
		catch (const CryptoPP::Exception& e)
		{
			std::cerr << e.what() << std::endl;
		}
	};

	CryptoPP::byte* new_sym_key() {
		CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
		CryptoPP::AutoSeededRandomPool asrp;
		asrp.GenerateBlock(key, sizeof(key));
		return key;
	}
};