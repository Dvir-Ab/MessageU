#include "utils.h"

/*----------------------------------------------------------
*	print the string, str, to ostrm in hex				  *
*														  *
*  ostrm - stream for printing							  *
*  str - string to print as hex							  *
----------------------------------------------------------*/
void printStrAsHex(std::ostream& ostrm, std::string str)
{
	for (auto c : str)
		ostrm << std::hex << unsigned((unsigned char)c);
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
unsigned short chrArr_to_ushort(const char* arr, bool isBigEndian) {
	if (std::strlen(arr) != sizeof(unsigned short)) {
		throw std::length_error("error: trying to change, \'%s\' , to short.");
	}
	if (isBigEndian) {
		return (((CryptoPP::byte)arr[0]) << 8) | (CryptoPP::byte)arr[1];
	}
	return  (((CryptoPP::byte)arr[1]) << 8) | (CryptoPP::byte)arr[0];
}
unsigned int net_uchr_to_uint_host(const char* chrp, bool isBigEndian) {
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

std::string store_ushort(unsigned short us, bool isBigEndian) {
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

std::string store_uint(unsigned int ui, bool isBigEndian) {
	std::string res = "";
	if (isBigEndian) {
		res += store_ushort(ui >> 8, isBigEndian) + store_ushort((unsigned short)ui, isBigEndian);
	}
	else {
		res += store_ushort((unsigned short)ui, false) + store_ushort(ui >> 8, false);
	}
	return res;
}