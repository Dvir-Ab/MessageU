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
	std::string data(bool isBigEndian = false) { return RequastHeader::data(isBigEndian); }
};

