#include <cryptlib.h>
#include <cstdlib>
#include <utility>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/endian.hpp>
#include <osrng.h>
#include <files.h>
#include "utils.h"

#define UID_LEN 16

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
		}catch (const std::exception& e){
			std::cerr << e.what() << std::endl;;
			throw ConnectionException::exception(e);//failed to connect
		}
	};


	void disconnect() {
		if (this->_skt.is_open()) {
			this->_skt.close();
		}
	};
};

class RequestHandler : public ConnHandler {
	FriendsManager * _frnds_mngr;
	std::string _host, _port;

	std::string get_name_from_user() {
		std::cout << "Please enter the target user name." << std::endl;
		std::string input;
		std::getline(std::cin, input);
		if (!this->_frnds_mngr->exist(input)) {
			std::cerr << "Unrecognized user name recieved." << std::endl;
			throw ExceptionLogger();
		}
		if (input.empty()) {
			std::cerr << "Excpect for the target user name but no input recieved." << std::endl;
			return "";
		}
		if (input.size() > MAX_NAME_LEN) {
			std::cerr << "The input name is too big." << std::endl;
			return "";
		}
		return input;
	}

	std::string newHeader(const uint8_t code, uint32_t payloadSize, std::string pld="") {
		return RequastHeader(this->_frnds_mngr->getSelf().getUid(), code, payloadSize, pld).data();
	}

	size_t sendSome(const std::string& msg) {
		if (this->_skt.is_open() && !msg.empty()){
			try {
				size_t writen = boost::asio::write(_skt, boost::asio::buffer(msg, msg.size()));// , boost::asio::transfer_all());
				return writen;
			}catch (const std::exception& e) {
				std::cout << "The connection with the server got broken." << std::endl;
				throw ExceptionLogger(e);
			}
		}
		return 0;
	};

	size_t sendRequest(const std::string& msg) {
		this->connect(this->_host, this->_port);
		log_stuff("sending request to: " + this->_host + ", of size: " + std::to_string(msg.size()));
		size_t writen = this->sendSome(msg);
		this->disconnect();
		log_stuff("successfully sent " + std::to_string(writen) + " bytes to: " + this->_host);
		return writen;
	};

	void registertion() {
		if (boost::filesystem::exists("me.info")) {
			std::cout << "\nerror: can not register again." << std::endl;
			throw ExceptionLogger();
		}
		std::cout << "Please enter a user name." << std::endl;
		std::string pubK,input;
		std::getline(std::cin, input);
		if (input.empty() || input.size() > MAX_NAME_LEN) 
			throw ExceptionLogger("name length error.");
		log_stuff("starting the registertion of " + input);
		Friend me(input);
		// init the pair of asymetric keys and read the public key and send it to the server for registration
		MyCipher cipher;
		cipher.init("me");
		CryptoPP::FileSource file("me.pub", true, new CryptoPP::Base64Decoder( new CryptoPP::StringSink(pubK)));
		me.setPub(pubK);
		this->_frnds_mngr->setSelf(me);
		reverseIfBigEndian(input);
		reverseIfBigEndian(pubK);
		std::string pld = input + pubK;
		sendRequest(RequastHeader(UserId(), ClientCodes::REGISTRETION, pld.size(), pld).data());
	};

	void pub_key() {
		std::string input = this->get_name_from_user();
		if(!this->_frnds_mngr->exist(input)){
			std::cerr << "Unrecognized user name recieved." << std::endl;
			throw ExceptionLogger();
		}
		log_stuff("starting a request for public key of " + input);
		std::string uidStr = this->_frnds_mngr->getFriend(input).getUid().data();
		reverseIfBigEndian(uidStr);
		sendRequest(newHeader(ClientCodes::GETPUB, uidStr.size(), uidStr));
	};

	// get msgs\clients list
	void simpleReq(const int8_t code) { sendRequest(newHeader(code, 0)); };
	/**/
	std::tuple<std::string> send_msg(CryptoPP::byte type) {
		MyCipher myCip;
		std::string encrypted = "", msg , name = this->get_name_from_user();
		if (!this->_frnds_mngr->exist(name)) throw ExceptionLogger();
		Friend target = this->_frnds_mngr->getFriend(name);
		if (type == ClientCodes::SYM_REQ) { //do nothing
		}else if (type == ClientCodes::SEND_SYM) {
			if (!target.havePubKey()) {
				std::cout << "Can\'t decrypt message! target\'s public key is missing." << std::endl;
				return ("","");
			}
			std::string symKey = myCip.new_sym_key();
			target.setSym(symKey);
			this->_frnds_mngr->setFriend(target.getName(), target);
			encrypted = myCip.encrypt_sym_with_pub(symKey, target.getPub());
		}else if (type == ClientCodes::TXT_MSG) {
			std::cout << "Please enter the message that you want to send:" << std::endl;
			std::string pld , input = "";
			std::getline(std::cin, input);// , '\n');
			if (input.empty()) { throw ExceptionLogger(); }
			encrypted = input;
		}else if (type == ClientCodes::FILE_MSG) {
			std::cout << "Please enter the full fule path of the file that you want to send:" << std::endl;
			std::string input;
			std::getline(std::cin, input);
			if (input.empty()) { throw ExceptionLogger("file path missing"); }
			this->sendBigMsg(input, target);
			return ("", "");
		}else { throw ExceptionLogger(); } // not a recognized type of msg
		if (type == ClientCodes::FILE_MSG || type == ClientCodes::TXT_MSG) {
			if (!this->_frnds_mngr->exist(name)) {
				std::cout << "Can\'t decrypt message! target\'s symmetric key is missing." << std::endl;
				return ("", "");
			}
			if (target.getSym().empty()) throw ExceptionLogger();
			std::string pld;
			encrypted = myCip.encrypt_with_sym(target.getSym(), encrypted);
		}
		msg = MessageHeader(target.getUid(), type, encrypted.size(), encrypted).data();
		sendRequest(RequastHeader((_frnds_mngr->getSelf()).getUid(), ClientCodes::SENDMSG, msg.size(), msg).data());
		return (name, encrypted);
	};
	

	void sendBigMsg(const std::string & filename, Friend & trgt) {
		boost::filesystem::path filePath(filename);
		if (!boost::filesystem::exists(filePath) || !boost::filesystem::is_regular_file(filePath)) { throw ExceptionLogger("file not found"); }
		if (filePath.filename().string().compare("me.info") == 0) { throw ExceptionLogger("restrict file path"); }
		uint64_t sent = 0, filesize = boost::filesystem::file_size(filePath);
		if (filesize >= INT32_MAX){
			std::cout << "The file: " << '\'' << filename << '\'' << ", is too big to send." << std::endl;
			return;
		}
		boost::filesystem::ifstream ifs(filePath, std::ios::binary | std::ios::in);
		log_stuff("trying to send a file of size: " + std::to_string(filesize));
		if (ifs) {
			ifs.seekg(0, ifs.end);
			std::cout << "\n" << ifs.tellg() << std::endl;
			ifs.seekg(0, ifs.beg);
			const uint32_t block_size = 1 << 24;
			std::string enc, sym = trgt.getSym();
			std::vector<char> buff;
			bool round1 = true;
			MyCipher cp;
			buff.assign(block_size, '\0');
			std::cout << "Strart to transfer the file: " << filename << ". it may take a while." << std::endl;
			while (!ifs.eof()) {
				ifs.read(buff.data(), block_size);
				if (ifs.gcount() != (std::streamsize)block_size) {
					buff.erase(buff.begin() + ifs.gcount(), buff.end());
				}
				enc = cp.encrypt_with_sym(sym, std::string(buff.begin(), buff.end()));
				if (round1) {
					std::string msg = MessageHeader(trgt.getUid(), ClientCodes::FILE_MSG, filesize, enc).data();
					enc = RequastHeader((_frnds_mngr->getSelf()).getUid(), ClientCodes::SENDMSG, sizeof(uint32_t) + filesize + AES_SIZE + 1, msg).data();
					round1 = false;
					this->connect(this->_host, this->_port);
				}
				this->sendSome(enc);
				sent += enc.size(); 
				std::cout << std::to_string(((sent / filesize) * 100)) << "% of the file has transfered." << std::endl;
			}
			ifs.close();
			log_stuff("successfully loaded, " + std::to_string(sent) + " bytes from the file");
			this->disconnect();
			return;
		}
		std::cout << "Faild to send the file " << filename << std::endl;
	}

public:
	RequestHandler(boost::asio::io_context& io_context, FriendsManager * fm, std::string host, std::string port)
		:_host(host), _port(port), _frnds_mngr(fm) , ConnHandler(io_context) {	};

	void handle(CryptoPP::byte req) {
		if (!req) {
			exit(0);
		}else if(req == 1){
			this->registertion();
			return;
		}
		if (!this->_frnds_mngr->isInit()) {
			std::cout << "You need to register to do this operation!" << std::endl;
			throw std::exception("not registered");
		}
		switch (req) {
		case 2:
			this->simpleReq(ClientCodes::USERLIST);
			return;
		case 3:
			this->pub_key();
			return;
		case 4:
			this->simpleReq(ClientCodes::PULL_MSG);
			return;
		case 5:	// send text msg
			this->send_msg(ClientCodes::TXT_MSG);
			return;
		case 50:
			this->send_msg(ClientCodes::FILE_MSG);
			return;
		case 51:
			this->send_msg(ClientCodes::SYM_REQ);
			return;
		case 52:
			this->send_msg(ClientCodes::SEND_SYM);
			return;
		default:
			std::cout << "Error: not a valid request." << std::endl;
			throw ExceptionLogger("invalid request code.");
		}
	};
};


class ResponseHandler  {
	size_t read(std::string& buff, size_t maxBytes = 128u) {
		if (maxBytes == 0) { return maxBytes; }
		size_t totalCnt = 0, reply_length, leftToRead = maxBytes, toTransfer = (maxBytes < MAX_LEN) ? maxBytes : MAX_LEN;
		boost::asio::streambuf sb(MAX_LEN+1);
		boost::system::error_code ec;
		buff.clear();
		buff.reserve(toTransfer);
		try{
			do{
				reply_length = boost::asio::read(*_skt, sb, boost::asio::transfer_at_least(toTransfer), ec);
				buff += std::string(boost::asio::buffers_begin(sb.data()), boost::asio::buffers_begin(sb.data()) + sb.size());
				sb.consume(sb.size());
				leftToRead -= reply_length;
				totalCnt += reply_length;
			} while (leftToRead < MAX_LEN && reply_length != 0);
			return totalCnt;
		}catch (const std::exception&e){
			std::cerr << e.what() << std::endl;
			throw ExceptionLogger(e);
		}
		return 0;
	}

	std::string readPulledMsg(std::string data,uint32_t length) {
		std::string userId, cntnt;
		uint32_t i = 0, msgID, cntnt_size;
		if (length > data.length()) {
			std::string tmp_buff;
			this->read(tmp_buff, length - data.length());
			data += tmp_buff;
		}
		const size_t minSize = 2 * sizeof(uint32_t) + 1;
		if (data.empty()) return "";
		data = data.substr(0, length);
		MyCipher myCip;
		while (!data.empty() && data.size() > i) {
			try{
				userId = data.substr(i, UID_LEN);
				i += UID_LEN;
				msgID = net_uchr_to_uint_host(data.substr(i,sizeof(uint32_t)).c_str());
				if (msgID == 0) break;
				i += sizeof(uint32_t);
				uint8_t msgType = data[i++];
				cntnt_size = net_uchr_to_uint_host(data.substr(i, sizeof(uint32_t)).c_str());
				i += sizeof(uint32_t);
				Friend msgSrc;
				try {
					msgSrc = this->_frnds_mngr->getFriendName(UserId(userId));
				}catch(const std::exception& e){
					i += cntnt_size;
					continue;
				}
				if (msgType == ClientCodes::SYM_REQ) {
					cntnt = "Request for symmetric key.";
				}else if (msgType == ClientCodes::SEND_SYM) {
					cntnt = "Symmetric key received.";
					std::string prvkey;
					std::ifstream ifs("me.info");
					for (int i = 0; i < 2; i++) std::getline(ifs, prvkey);
					CryptoPP::FileSource fs(ifs, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(prvkey)));
					msgSrc.setSym(myCip.decryptKey(prvkey, data.substr(i, CryptoPP::AES::DEFAULT_KEYLENGTH * 8)));
					i += CryptoPP::AES::DEFAULT_KEYLENGTH * 8;
					//data = data.substr(CryptoPP::AES::DEFAULT_KEYLENGTH, data.size() - CryptoPP::AES::DEFAULT_KEYLENGTH);
				}else if (msgType == ClientCodes::TXT_MSG || msgType == ClientCodes::FILE_MSG) { //msg is txt or file, need to decrypy cntnt with sym key
					std::string tmp = "", symStr;
					if (data.size() - i < cntnt_size) this->read(tmp, cntnt_size + i - data.size());
					data += tmp;
					symStr = msgSrc.getSym();
					//if (symStr.size() != CryptoPP::AES::DEFAULT_KEYLENGTH * 8) { throw ExceptionLogger("symmetric key missing!"); }
					cntnt = myCip.decryptData(msgSrc.getSym(), data.substr(i,cntnt_size));
					if (msgType == ClientCodes::FILE_MSG) { // write the cntnt to tmp file in ./%TMP% folder
						if (!boost::filesystem::exists("%TMP%")) {
							boost::filesystem::create_directory("%TMP%");
						}
						std::string path = ".\\%TMP%\\" + msgSrc.getName() + std::to_string(msgID), absPath;
						absPath= boost::filesystem::current_path().string() + path.substr(1);
						boost::filesystem::ofstream output(path, std::ios::out);
						output << cntnt << std::endl;
						output.close();
					}
					i += cntnt_size;
				}else { throw ExceptionLogger("Message type error!"); }
				this->_frnds_mngr->setFriend(msgSrc.getName(), msgSrc);
				std::cout << "From: " << msgSrc.getName() << std::endl;
				std::cout << "Content: " << std::endl;
				std::cout << cntnt << std::endl;
				std::cout << "--------EOM-------- " << std::endl;
			}catch (const std::exception& e ){
				std::cerr << e.what() << std::endl;
			}
			//data = data.substr(i, data.size());
			//data.erase(std::find(data.begin(), data.end(), '\0'), data.end());
		}
		return "";
	}

	void registrationComplete(std::string data) {
		if (data.size() != AES_SIZE || !boost::filesystem::exists("me.prv")) {
			std::cout << "Something went wrong in the registration process." << std::endl;
			return;
		}
		reverseIfBigEndian(data);
		Friend myself = this->_frnds_mngr->getSelf();
		UserId myuid;
		myuid.setData(data);
		myself.setUid(myuid);
		this->_frnds_mngr->setSelf(myself);
		std::string idsink, myUname = myself.getName(), keysink;
		CryptoPP::StringSource strsrc(data.c_str(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(idsink)));
		CryptoPP::FileSource fs("me.prv", true, new CryptoPP::StringSink(keysink));

		boost::filesystem::ofstream out;
		out.open("me.info", std::ios::out);
		out << myUname.c_str() << std::endl;
		out << idsink << std::endl;
		out << keysink;
		out.close();
		std::cout << "The registration has been done successfully" << std::endl;
		log_stuff("The registration process of '" + myUname + "', has been successfully completed.");
	}

	void receiveUserList(std::string data) {
		enum { NAME_LEN =255};
		//data.shrink_to_fit();
		std::string uidstr,sym = (this->_frnds_mngr->getSelf()).getSym(); ///// remove this line after testing!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		log_stuff("received the users list from the server.");
		while (data.size() > UID_LEN + NAME_LEN) {
			Friend f;
			UserId uid;
			uidstr = data.substr(0, UID_LEN);
			uidstr.erase(std::find(uidstr.begin(), uidstr.end(), '\0'), uidstr.end());
			if (uidstr.empty()) break;
			uid.setData(uidstr);
			f.setUid(uid);
			f.setName(data.substr(UID_LEN, NAME_LEN));
			f.setSym(sym); ///// remove this line after testing!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			this->_frnds_mngr->setFriend(f.getName(),f);
			std::cout << "User name: " << f.getName() << std::endl;
			data = data.substr(UID_LEN + NAME_LEN, data.size() - (UID_LEN + NAME_LEN));
		}
		log_stuff("The users list saved.");
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

