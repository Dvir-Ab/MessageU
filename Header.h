#include <cryptlib.h>
#include <cstdlib>
#include <utility>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/endian.hpp>
#include <osrng.h>
#include <files.h>
#include <thread>
#include "utils.h"


#define UID_LEN 16
#define MAX_LEN 1024



class ConnHandler {
protected:
	boost::asio::ip::tcp::socket _skt;
	boost::asio::ip::tcp::resolver _resolver;
public:
	ConnHandler(boost::asio::io_context& io_context) : _skt(io_context) , _resolver(io_context){};
	void connect(std::string host,std::string port) {
		if (this->_skt.is_open()) {
			return;
		}
		try {
			boost::asio::connect(this->_skt, this->_resolver.resolve(host,port));
		}
		catch (const std::exception& e){
			std::cerr << e.what() << std::endl;;
			throw std::exception(e);//failed to connect
		}
	};

	void disconnect() {
		if (this->_skt.is_open()) {
			this->_skt.close();
		}
	};
};



class RequestHandler : public ConnHandler {
	const size_t MAX_NAME_LEN = 255;
	enum { REG = 100, };
	FriendsManager * _frnds_mngr;
	std::string _host, _port;

	std::string get_name_from_user() {
		std::cout << "Please enter the target user name." << std::endl;
		std::string input;
		std::getline(std::cin, input);// , '\n');
		if (input.empty()) {
			std::cerr << "Excpect for the target user name but no input recieved." << std::endl;
			return "";
		}
		if (input.size() > MAX_NAME_LEN) {
			std::cerr << "The input name is too big." << std::endl;
			return "";
		}
		/*if (this->_frnds_lst.find(input) == this->_frnds_lst.end())  { //(input.size() != 16u) {
			std::cerr << "The user name : " << input << " , is not reognized." << std::endl;
			return "";
		}*/
		return input;
	}

	std::string newHeader(const uint8_t code, uint32_t payloadSize, std::string pld="") {
		return RequastHeader(this->_frnds_mngr->getSelf().getUid(), code, payloadSize, pld).data();
	}

	size_t sendRequest(const std::string& msg) {
		try{
			this->connect(this->_host, this->_port);
			size_t writen = boost::asio::write(_skt, boost::asio::buffer(msg, msg.size()));
			this->disconnect();
			return writen;
		}catch (const std::exception& e){
			std::cerr << e.what() << std::endl;
		}
		return 0;
	};

	void registertion() {
		if (boost::filesystem::exists("me.info")) {
			std::cout << "\nerror: can not register again." << std::endl;
			return;
		}
		const int8_t CODE = 100;
		std::cout << "Please enter a user name." << std::endl;
		std::string pubK,input;
		std::getline(std::cin, input);
		if (input.empty() || input.size() > MAX_NAME_LEN) {
			throw std::exception("name length error.");
		}
		// TODO: add try catch block !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		Friend me(input);
		// write the user name in me.info
		/*input.append("\0");
		boost::filesystem::ofstream out;
		out.open("me.info", std::ios::out);
		out.write(input.c_str(), input.size());
		out.close();*/
		// init the pair of asymetric keys and read the public key and send it to the server for registretion
		MyCipher cipher;
		cipher.init("me");
		CryptoPP::FileSource file("me.pub", true, new CryptoPP::HexDecoder( new CryptoPP::StringSink(pubK)));
		me.setPub(pubK);
		this->_frnds_mngr->setSelf(me);
		std::reverse(input.begin(), input.end());
		std::reverse(pubK.begin(), pubK.end());
		std::string pld = input + pubK;
		sendRequest(RequastHeader(UserId(), CODE, pld.size(), pld).data());
	};

	std::string pub_key() {
		const int8_t CODE = 103;
		std::cout << "Please enter the target user name." << std::endl;
		std::string input;
		std::getline(std::cin, input);
		if (input.empty()) {
			std::cerr << "Excpect for the target user name but no input recieved." << std::endl;
			return "";
		}else if(!this->_frnds_mngr->exist(input)){
			std::cerr << "Unrecognized friend user name recieved." << std::endl;
			return "";
		}
		input.reserve();
		sendRequest(newHeader(CODE, input.size(), input)); //uchrsToBytes(input, 2 * sizeof(uint64_t), false));
	};

	void simpleReq(const int8_t code) { // get msgs\clients list
		sendRequest(newHeader(code, 0));
	};
	/**/
	std::tuple<std::string> send_msg(CryptoPP::byte type) {
		MyCipher myCip;
		const int8_t CODE = (int8_t)103 ,SYM_REQ = (int8_t) 1, SEND_SYM = (int8_t)2, SEND_MSG = (int8_t)3, SEND_FILE = (int8_t)4;
		std::string encrypted, msg , name = this->get_name_from_user();
		if (!this->_frnds_mngr->exist(name)) throw std::exception();
		Friend *target = this->_frnds_mngr->getFriend(name);
		//msg.push_back(type);
		if (type == SYM_REQ) {
			msg += store_uint(0u,false);
		}
		else if (type == SEND_SYM) {
			//check for pub key in friends list
			//add lock on friends list ->  get friend by name as f -> lock f and unlock friends list -> set symbol key in f and get pub_key from f -> unlock f 
			//Friend f = this->_frnds_mngr->getFriend(name);
			if (!target->havePubKey()) {
				std::cout << "Can\'t decrypt message! target\'s public key is missing." << std::endl;
				return ("","");
			}
			CryptoPP::byte* symKey = myCip.new_sym_key();
			target->setSym(std::string((char *)symKey));
			encrypted = myCip.encrypt_sym_with_pub(symKey, target->getPub());
		}
		else if (type == SEND_MSG) {
			std::cout << "\nPlease enter the message that you want to send:" << std::endl;
			std::string pld , input = "";
			std::getline(std::cin, input);// , '\n');
			if (input.empty()) { throw std::exception(); }
			encrypted = input;
		}
		else if (type == SEND_FILE) {
			std::cout << "\nPlease enter the full fule path of the file that you want to send:" << std::endl;
			std::string input;
			std::getline(std::cin, input);// , '\n');
			if (input.empty()) { throw std::exception(); }
			boost::filesystem::path filePath(input);
			if (!boost::filesystem::exists(filePath)) { throw std::exception(); }
			boost::filesystem::ifstream in(filePath, std::ios::binary | std::ios::in);
			std::ostringstream cntx;
			cntx << in.rdbuf();
			in.close();
			encrypted = cntx.str();
		}
		else { throw std::exception(); } // not a recognized type of msg
		if (type == SEND_FILE || type == SEND_MSG) {
			if (!this->_frnds_mngr->exist(name)) {
				std::cout << "Can\'t decrypt message! target\'s symmetric key is missing." << std::endl;
				return ("", "");
			}
			//Friend f = this->_frnds_mngr->getFriend(name);
			if (target->getSym() == nullptr) throw std::exception();
			std::string pld;
			pld = myCip.encrypt_with_sym(target->getSym(), encrypted);
			pld.reserve();
			encrypted = pld;
		}
		msg = MessageHeader(target->getUid(), type, encrypted.size(), encrypted).data();
		sendRequest(RequastHeader((_frnds_mngr->getSelf()).getUid(), CODE, msg.size(), msg).data());
		return (name, encrypted);
	};
	
public:
	RequestHandler(boost::asio::io_context& io_context, FriendsManager * fm, std::string host, std::string port)
		:_host(host), _port(port), _frnds_mngr(fm) , ConnHandler(io_context) {
		//this->_ciper.init();
	};

	void handle(CryptoPP::byte req) {
		if (!req) {
			exit(0);
		}
		try {
			switch (req) {
			case 1:
				this->registertion();
				break;
			case 2:
				this->simpleReq((CryptoPP::byte)101);
				break;
			case 3:
				this->pub_key();
				break;
			case 4:
				this->simpleReq((CryptoPP::byte)104);
				break;
			case 5:	case 50:	case 51:	case 52:
				this->send_msg(req % 10);
				break;
			default:
				break;
			}
		}catch(std::exception &e){
			std::cerr << e.what() << std::endl;
		}
	};
};


class ResponseHandler  {
	size_t read(std::string& buff, size_t maxBytes = 128u) {
		if (maxBytes == 0) { return maxBytes; }
		size_t totalCnt = 0, reply_length, leftToRead = maxBytes;//, toTransfer = (maxBytes < MAX_LEN) ? maxBytes : MAX_LEN;
		boost::asio::streambuf sb(MAX_LEN+1);
		boost::system::error_code ec;
		std::string tmp_buff = "";
		buff.clear();
		try
		{
			do
			{
				reply_length = boost::asio::read(*_skt, sb, boost::asio::transfer_exactly(MAX_LEN), ec);
				buff = std::string(boost::asio::buffers_begin(sb.data()), boost::asio::buffers_begin(sb.data()) + sb.size());
				sb.consume(sb.size());
				leftToRead -= reply_length;
				totalCnt += reply_length;
			} while (leftToRead < MAX_LEN && reply_length != 0);
			return totalCnt;
		}
		catch (const std::exception&e)
		{
			std::cerr << e.what() << std::endl;
			throw std::exception(e);
		}
		return 0;
	}

	std::string readPulledMsg(std::string data) {
		std::string userId, cntnt;
		size_t i, msgID;
		while (true) {
			i = 0;
			userId = data.substr(i, UID_LEN);
			i += UID_LEN;
			msgID = net_uchr_to_uint_host(data.substr(i, sizeof(size_t)).c_str(), false);
			i += sizeof(uint32_t);
			uint16_t msgType = chrArr_to_ushort(data.substr(UID_LEN, sizeof(uint16_t)).c_str(), false);
			i += sizeof(uint16_t);
			uint32_t cntnt_size = net_uchr_to_uint_host(data.substr(i, sizeof(uint32_t)).c_str(), false);
			i += sizeof(uint32_t);
			if (msgType == (uint16_t)1) {
				cntnt = "Request for symmetric key.";
			}
			else if (msgType == (uint16_t)2) {
				cntnt = "Symmetric key received.";
				data = data.substr(UID_LEN + sizeof(uint16_t), data.size() - (UID_LEN + sizeof(uint16_t)));
				//decrypte_with_pubKey(data);
				boost::filesystem::ofstream out;
				out.open("friend.sym", std::ios::app | std::ios::hex);
				out << data;
				out.close();
			}
			else if (msgType == (uint16_t)3) { //txt msg , need to decrypy msg's cntnt with sym key
				boost::filesystem::ifstream in;
				std::string sym;
				in.open("freinds.sym", std::ios::in);
				in >> sym;
				in.close();
				CryptoPP::SecByteBlock decMsg;
				while (!sym.empty()) {
					if (sym.substr(0, UID_LEN) == userId) {
						//decrypt msg contnt with the key from sym.substr(UID_LEN,128) and print the decrypted msg
						std::string pubDecrypted = "";
						try {
							CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption dec;
							dec.SetKey(MyCipher().decrypt("me.pub", sym.substr(UID_LEN, 128u)), 128u); //decrypt symmetric key with public key
							if (cntnt_size > data.size() - i) {
								std::string cntnt_buff;
								if (this->read(cntnt_buff, cntnt_size - data.size() + i) == 0) {
									//error , expect to see cntnt in this msg
									throw std::exception();
								}
								data += cntnt_buff;
							}
							dec.ProcessData((CryptoPP::byte*)data.substr(i, data.size() - i).c_str(), (CryptoPP::byte*)decMsg, cntnt_size);
						}
						catch (std::exception& e) {
							std::cerr << e.what() << std::endl;
						}
						cntnt = std::string(decMsg.begin(), decMsg.end());
						break;
					}
					sym = sym.substr(UID_LEN + 128u, sym.size() - (UID_LEN + 128u));
				}
			}
			else if (msgType == (uint16_t)4) {

			}
			else { throw std::exception(); }
			std::cout << "From: " << userId << std::endl;
			std::cout << "Content: " << std::endl;
			std::cout << cntnt << std::endl;
			std::cout << "--------EOM-------- " << std::endl;
		}
	}

	void registretionComplete(std::string data) {
		if (data.size() != UserId::size) {
			//throw exception
			return;
		}
		std::reverse(data.begin(), data.end());
		Friend myself = this->_frnds_mngr->getSelf();
		UserId myuid;
		myuid.setData(data);
		myself.setUid(myuid);
		std::string myUname = myself.getName();
		boost::filesystem::ofstream out;
		out.open("me.info", std::ios::out);
		out << myUname.c_str() << std::endl;
		printStrAsHex(out, data);
		out.close();
	}

	void receiveUserList(std::string data) {
		enum { NAME_LEN =255};
		while (data.size() > UID_LEN + NAME_LEN) {
			Friend f;
			UserId uid;
			uid.setData(data.substr(0, UID_LEN));
			f.setUid(uid);
			f.setName(data.substr(UID_LEN, NAME_LEN));
			this->_frnds_mngr->setFriend(f.getName(),f);
			std::cout << "User name: " << f.getName() << std::endl;
			data = data.substr(UID_LEN + NAME_LEN, data.size() - (UID_LEN + NAME_LEN));
		}
	}

	FriendsManager* _frnds_mngr;

	boost::asio::ip::tcp::socket * _skt;
public:
	ResponseHandler(boost::asio::ip::tcp::socket * sock,FriendsManager* friendsMngr){
		this->_frnds_mngr = friendsMngr;
		this->_skt = sock;
	};
	
	void response();
};

