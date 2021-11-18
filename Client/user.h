
#ifndef __USER__
#define __USER__

#include <osrng.h>
typedef struct UserId {
public:
	//~UserId() { delete[] this->uid; }

	enum { size = 16 };
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
		std::string res((char*)this->uid, this->size);
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

#endif // !__USER__