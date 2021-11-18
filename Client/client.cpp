#include "client.h"

using namespace CLIENT;

void Client::loadSelfInfo() {
	if (!boost::filesystem::exists("me.info")) {
		return;
	}
	boost::filesystem::ifstream infoIn;
	std::string name, id, idsink;
	Friend self = this->_fm.getSelf();
	infoIn.open("me.info");
	std::getline(infoIn, name);
	std::getline(infoIn, id);
	infoIn.close();
	UserId uid;
	CryptoPP::StringSource strsrc(id.c_str(), true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(idsink)));
	uid.setData(idsink);
	this->_fm.setSelf(Friend(name, uid));
}

std::string Client::readInput() {
	std::string res = "", line;
	while (std::getline(std::cin, line))
	{
		res += line;
	}
	return res;
}

void Client::interact() {
	boost::asio::io_context io_context;
	RequestHandler rh(io_context, &this->_fm, this->_host, this->_port);// , this->endP);

	std::cout << "MessageU client at your service." << std::endl;
	std::cout << "\n 1) Register\n 2) Request for client list\n 3) Request for public key\n"
		<< " 4) Request for waiting messages\n 5) Send a text message\n 50) Send a file"
		<< "\n 51) Send a request for symmetric key\n 52) Send your symmetric key\n 0) Exit\n"
		<< "Please enter the options." << std::endl;
	std::string input;
	std::getline(std::cin, input);
	try {
		rh.handle(std::stoi(input));
	}
	catch (...) {
		std::cerr << "Error: wrong input!";
	}
}

void Client::handleResponse() {
	try
	{
		boost::asio::io_context io_context;
		//std::cout << boost::asio::ip::address::from_string("127.0.0.1") << "\t" << this->_port << std::endl; //boost::asio::ip::address::from_string("127.0.0.1")
		boost::asio::ip::tcp::acceptor acc(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 8080));
		//for (;;) {
		boost::asio::ip::tcp::socket sock = acc.accept();
		ResponseHandler rh(&sock, &_fm);
		rh.response();
		//}
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
};

void Client::start() {
	//boost::asio::io_context io_context;
	//std::thread(&Client::handleResponse,this).detach();
	for (;;) {
		try {
			this->interact();// , this->_friends);
			//ResponseHandler rsh(&_fm);
			std::thread(&Client::handleResponse, this).detach();
		}
		catch (const std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
	}
}