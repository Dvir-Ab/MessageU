#include "Header.h"

std::string loadSym() {
	if (!boost::filesystem::exists("key.sym")) {
		MyCipher cip;
		std::ofstream out("key.sym", std::ios::out);
		out << cip.new_sym_key() << std::flush;
		out.close();
	}
	std::string res;
	std::ifstream in("key.sym", std::ios::in);
	std::getline(in, res);
	return res;
}

class Client {
private:

	void loadSelfInfo() {
		log_stuff("client start.");
		if (!boost::filesystem::exists("me.info")) {
			return;
		}
		boost::filesystem::ifstream infoIn;
		std::string name,id,idsink;
		Friend self;
		try{
			infoIn.open("me.info");
			std::getline(infoIn, name);
			std::getline(infoIn, id);
			infoIn.close();
			self.setName(name);
			UserId uid;
			CryptoPP::StringSource strsrc(id.c_str(), true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(idsink)));
			uid.setData(idsink);
			self.setUid(uid);
			self.setSym(loadSym());
			this->_fm.setSelf(self);
		}catch (const std::exception& e){
			std::cerr << e.what() << std::endl;
		}
	}

	FriendsManager _fm;
	std::string _host, _port;
public:
	Client() : _fm() {
		try
		{
			boost::filesystem::ifstream input;
			input.open("server.info");
			if (!std::getline(input, this->_host, ':')) throw ExceptionLogger("Error: the host\'s address in the file: \'server.info\' is not right.");
			if(!std::getline(input, this->_port)) throw ExceptionLogger("Error: the port in the file: \'server.info\' is not right.");
			input.close();

			this->loadSelfInfo();
		}catch (const std::exception& e){
			std::cerr << e.what() << "\nClient constructor failed" << std::endl;
		}
	};

	void interact();

	void handleResponse() {
		try{
			boost::asio::io_context io_context;
			boost::asio::ip::tcp::acceptor acc(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 8080));
			boost::asio::ip::tcp::socket sock = acc.accept();
			ResponseHandler rh(&sock,&this->_fm);
			rh.response();
		}catch (const std::exception& e){
			log_stuff(e.what());
		}
	};

	void start() {
		log_stuff("client runing.");
		for (;;) {
			try{
				this->interact();
				this->handleResponse();
			}catch (const std::exception& e){
				log_stuff(e.what());
			}
		}
	}
};