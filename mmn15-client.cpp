
#include "client.h"


void ResponseHandler::response() {
	struct {
		CryptoPP::byte ver;
		uint16_t code;
		uint32_t pld_size;
	} hdr;
	//this->accept();
	const size_t PUB_LEN = 32, NAME_LEN = 255;
	enum { REGISTRATION_RESULT = (uint16_t)1000 , USRS_LST, PUB_REQ , PULLED_MSGS , GNRL_ERR = (uint16_t)9000};
	size_t reply_length, ind = 0;
	std::string data;
	try {
		reply_length = this->read(data);
		//check data length !!!!!!!!!!!!!!!!!!!!!!!!!!!
		ind += sizeof(hdr.ver) + sizeof(hdr.code) + sizeof(hdr.pld_size);
		if (data.size() < ind || reply_length < ind) {
			// log this
			return;
		}
		// fill hdr
		hdr = { (CryptoPP::byte)data[0], chrArr_to_ushort(data.substr(1, 2).c_str()), net_uchr_to_uint_host(data.substr(3, 4).c_str()) };
		data = data.substr(ind, data.size() - ind);
		if (hdr.code == GNRL_ERR) { //general server error
			std::cout << "General server error." << std::endl;
			return;
		}
		if (hdr.code == REGISTRATION_RESULT) { // registeration result
			//check if payload size is 16 bytes!!!!!
			this->registretionComplete(data.substr(0, UserId::size));
			//print some thing!!
			return;
		}
		else if (hdr.code == USRS_LST) { // users list returned, print it to the user
			std::string payloadData;
			if (data.size() < hdr.pld_size) {
				reply_length = this->read(payloadData, hdr.pld_size - data.size());
				data += payloadData;
			}
			this->receiveUserList(data);
			return;
		}
		else if (hdr.code == PUB_REQ) { //pub key 
			if (hdr.pld_size != UID_LEN + PUB_LEN || hdr.pld_size != data.size()) { throw std::exception(); }
			boost::filesystem::ofstream out;
			out.open("friends.pub", std::ios::hex | std::ios::app);
			out << data;
			out.close();
		}
		else if (hdr.code == PULLED_MSGS) { //read the pulled msgs
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
	}
	catch (std::exception& e) {}
}

//void Client::interact() {
//	boost::asio::io_context io_context;
//	RequestHandler rh(io_context, &this->_fm, this->_host, this->_port);// , this->endP);
//
//	std::cout << "MessageU client at your service." << std::endl;
//	std::cout << "\n 1) Register\n 2) Request for client list\n 3) Request for public key\n"
//		<< " 4) Request for waiting messages\n 5) Send a text message\n 50) Send a file"
//		<< "\n 51) Send a request for symmetric key\n 52) Send your symmetric key\n 0) Exit\n"
//		<< "Please enter the options." << std::endl;
//	std::string input;
//	std::getline(std::cin, input);
//	try {
//		rh.handle(std::stoi(input));
//	}
//	catch (...) {
//		std::cerr << "Error: wrong input!";
//	}
//}



int main(int argc, char* argv[]) {
	try {
		//boost::asio::io_context io_context;
		CLIENT::Client c;
		c.start();
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}
}