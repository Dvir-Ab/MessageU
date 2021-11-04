#include "Header.h"


class Client {
private:
	std::string readInput() {
		std::string res = "", line;
		while (std::getline(std::cin, line))
		{
			res += line;
		}
		return res;
	}

	void loadSelfInfo() {
		if (!boost::filesystem::exists("me.info")) {
			return;
		}
		boost::filesystem::ifstream infoIn;
		std::string name,id,idsink;
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

	FriendsManager _fm;
	std::string _host, _port;
public:
	Client() : _fm() {
		try
		{
			boost::filesystem::ifstream input;
			input.open("server.info");
			if (!std::getline(input, this->_host, ':')) throw std::exception("Error: the host\'s address in the file: \'server.info\' is not right.");
			if(!std::getline(input, this->_port)) throw std::exception("Error: the port in the file: \'server.info\' is not right.");
			input.close();

			this->loadSelfInfo();
		}catch (const std::exception& e){
			std::cerr << e.what() << "\nClient constructor failed" << std::endl;
		}
	};

	void interact();

	void handleResponse() {
		try
		{
			boost::asio::io_context io_context;
			//std::cout << boost::asio::ip::address::from_string("127.0.0.1") << "\t" << this->_port << std::endl; //boost::asio::ip::address::from_string("127.0.0.1")
			boost::asio::ip::tcp::acceptor acc(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 8080));
			//for (;;) {
				boost::asio::ip::tcp::socket sock = acc.accept();
				ResponseHandler rh(&sock,&_fm);
				rh.response();
			//}
		}catch (const std::exception& e){
			std::cerr << e.what() << std::endl;
		}
	};

	void start() {
		//boost::asio::io_context io_context;
		//std::thread(&Client::handleResponse,this).detach();
		for (;;) {
			try{
				this->interact();// , this->_friends);
				//ResponseHandler rsh(&_fm);
				std::thread(&Client::handleResponse,this).detach();
			}catch (const std::exception& e){
				std::cerr << e.what() << std::endl;
			}
		}
	}
};