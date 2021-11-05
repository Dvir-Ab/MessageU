#include "Friends.h"

Friend FriendsManager::getSelf() {
	const std::lock_guard<std::mutex> lock(this->_slf_mtx);
	Friend f = this->_myself;
	return f;
	// mutex will be unlocked (from lock destructor) when leaving the scope of lock
}
void FriendsManager::setSelf(const Friend& f) {
	const std::lock_guard<std::mutex> lock(this->_slf_mtx);
	this->_myself = f;
}

Friend* FriendsManager::getFriend(std::string name) {
	const std::lock_guard<std::mutex> lock(this->_otr_mtx);
	if (this->find(name) == this->end()) return nullptr;
	Friend f(this->operator[](name));
	return &f;
}

void FriendsManager::setFriend(std::string name, const Friend f) {
	const std::lock_guard<std::mutex> lock(this->_otr_mtx);
	(*this)[name] = f;
}

bool FriendsManager::exist(std::string user = "") {
	if (user.empty()) {
		const std::lock_guard<std::mutex> lock(this->_slf_mtx);
		return _myself.getName().empty();
	}
	const std::lock_guard<std::mutex> lock(this->_otr_mtx);
	return this->find(user) == this->end();
}