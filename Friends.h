#pragma once
#include "utils.h"

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

	Friend getSelf();
	void setSelf(const Friend& f);
	Friend* getFriend(std::string name);
	void setFriend(std::string name, const Friend f);
	bool exist(std::string user = "");
private:
	Friend _myself;
	std::mutex _slf_mtx, _otr_mtx;
};