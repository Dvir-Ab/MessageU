#include <cryptlib.h>
#include <utility>
#include <files.h>
#include <thread>
#include "Cypher.h"
#include "Friends.h"
#include "utils.h"



#define UID_LEN 16
#define MAX_LEN 1024



class ConnHandler {
protected:
	boost::asio::ip::tcp::socket _skt;
	boost::asio::ip::tcp::resolver _resolver;
public:
	ConnHandler(boost::asio::io_context& io_context) : _skt(io_context) , _resolver(io_context){};
	void connect(std::string host,std::string port);

	void disconnect();
};



class RequestHandler : public ConnHandler {
	const size_t MAX_NAME_LEN = 255;
	enum { REG = 100, };
	FriendsManager * _frnds_mngr;
	std::string _host, _port;

	std::string get_name_from_user();

	std::string newHeader(const uint8_t code, uint32_t payloadSize, std::string pld = "");

	size_t sendRequest(const std::string& msg);

	void registertion();

	std::string pub_key();

	void simpleReq(const int8_t code);  // get msgs\clients list
	/**/
	std::tuple<std::string> send_msg(CryptoPP::byte type);

	std::string send_sym(Friend* frnd, MyCipher& myCip);
	
public:
	RequestHandler(boost::asio::io_context& io_context, FriendsManager * fm, std::string host, std::string port)
		:_host(host), _port(port), _frnds_mngr(fm) , ConnHandler(io_context) {
		//this->_ciper.init();
	};

	void handle(CryptoPP::byte req);
};


class ResponseHandler  {
	size_t read(std::string& buff, size_t maxBytes = 128u);

	std::string readPulledMsg(std::string data);

	std::string decriptContect(const std::string& userId, uint32_t cntnt_size, std::string& data, size_t decriptedCnt);

	void registretionComplete(std::string data);

	void receiveUserList(std::string data);


	FriendsManager* _frnds_mngr;

	boost::asio::ip::tcp::socket * _skt;
public:
	ResponseHandler(boost::asio::ip::tcp::socket * sock,FriendsManager* friendsMngr){
		this->_frnds_mngr = friendsMngr;
		this->_skt = sock;
	};
	
	void response();
};

