
#ifndef __UTILS__
#define __UTILS__ 

	#include <cstdlib>
	#include <stdint.h>

	#include "user.h"

	/*----------------------------------------------------------
	*	print the string, str, to ostrm in hex				  *
	*														  *
	*  ostrm - stream for printing							  *
	*  str - string to print as hex							  *
	----------------------------------------------------------*/
	void printStrAsHex(std::ostream& ostrm, std::string str);


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
	unsigned short chrArr_to_ushort(const char* arr, bool isBigEndian = false);

	unsigned int net_uchr_to_uint_host(const char* chrp, bool isBigEndian = false);

	std::string store_ushort(unsigned short us, bool isBigEndian = false);
	std::string store_uint(unsigned int ui, bool isBigEndian = false);

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

#endif // end of __UTILS__