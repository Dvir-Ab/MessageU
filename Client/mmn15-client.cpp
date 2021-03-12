
#include "client.h"


void ResponseHandler::response() {
	struct {
		CryptoPP::byte ver;
		uint16_t code;
		uint32_t pld_size;
	} hdr;
	const size_t  NAME_LEN = 255;
	size_t reply_length, ind = 0;
	std::string data;
	log_stuff("handle server's response.");
	try {
		reply_length = this->read(data);
		ind += sizeof(hdr.ver) + sizeof(hdr.code) + sizeof(hdr.pld_size);
		if (data.size() < ind || reply_length < ind) {
			log_stuff("response is too small");
			return;
		}
		hdr = { (CryptoPP::byte)data[0], chrArr_to_ushort(data.substr(1,2).c_str()),net_uchr_to_uint_host(data.substr(3,4).c_str()) };
		data = data.substr(ind, data.size() - ind);
		if (hdr.code == ClientCodes::GNRL_ERR) { //general server error
			std::cout << "General server error." << std::endl;
			return;
		}
		if (hdr.code == ClientCodes::REGISTRATION_RESULT) { // registeration result
			this->registrationComplete(data.substr(0, AES_SIZE));
			return;
		}else if (hdr.code == ClientCodes::USRS_LST_RTN) { // users list returned, print it to the user
			std::string payloadData;
			if (data.size() < hdr.pld_size) {
				reply_length = this->read(payloadData, hdr.pld_size - data.size());
				data += payloadData;
			}
			this->receiveUserList(data);
			return;
		}else if (hdr.code == ClientCodes::PUB_REQ) { //pub key 
			if (hdr.pld_size != UID_LEN + RSA_SIZE) { std::cout << "missing data" << std::endl; return; }
			try {
				std::string uidStr = data.substr(0, UID_LEN);
				Friend frnd = this->_frnds_mngr->getFriendName(UserId(uidStr));
				frnd.setPub(data.substr(UID_LEN, RSA_SIZE));
				this->_frnds_mngr->setFriend(frnd.getName(), frnd);
				std::cout << "The public key of " << frnd.getName() << " received." << std::endl;
			}catch (std::exception& e) {
				std::cout << "Recived a public key from unknown source." << std::endl;
			}
		}else if(hdr.code == ClientCodes::MSG_RECEIVED){
			Friend dest = this->_frnds_mngr->getFriendName(UserId(data.substr(0, AES_SIZE)));
			std::cout << "The message with the id: " + std::to_string(net_uchr_to_uint_host(data.substr(AES_SIZE, sizeof(uint32_t)).c_str()))
				+ " saved and waiting for " + dest.getName() + " to pull it." << std::endl;
			this->_frnds_mngr->setFriend(dest.getName(), dest);
		}else if (hdr.code == ClientCodes::PULLED_MSGS) { //read the pulled msgs
			this->readPulledMsg(data,hdr.pld_size);
		}
	}catch (std::exception& e) {std::cerr << e.what() << std:: endl;}
}

void Client::interact() {
	std::cout << "MessageU client at your service." << std::endl;
	std::cout << "\n 1) Register\n 2) Request for client list\n 3) Request for public key\n"
		<< " 4) Request for waiting messages\n 5) Send a text message\n 50) Send a file"
		<< "\n 51) Send a request for symmetric key\n 52) Send your symmetric key\n 0) Exit\n"
		<< "Please enter the options." << std::endl;
	std::string input;
	std::getline(std::cin, input);
	boost::asio::io_context io_context;
	RequestHandler rh(io_context, &this->_fm, this->_host, this->_port);
	rh.handle(std::stoi(input));
}



void readFileq(const std::string& fname) {
	uint64_t filesize = boost::filesystem::file_size(fname);
	const uint32_t block_size = 1 << 24;
	std::ifstream ifs(fname,std::ios::in | std::ios::binary);
	std::ofstream ofs(fname.substr(0,fname.size()-4)+ "encrypted.txt",std::ios::out | std::ios::binary);
	MyCipher cp;
	std::string enc , sym = cp.new_sym_key();
	std::vector<char> buff;
	buff.reserve(block_size);
	if (ifs) {
		while (!ifs.eof()) {
			buff.assign(block_size,'\0');
			ifs.read(buff.data(), block_size);
			if (ifs.gcount() != block_size) 
				buff.erase(buff.begin() + ifs.gcount(), buff.end());
			enc = cp.encrypt_with_sym(sym, std::string(buff.begin(), buff.end()));
			ofs.write(enc.c_str(), enc.size());
		}
		ifs.close();
		ofs.close();
		return;
	}
	
	std::cout << "faild to read" << "\n";
}



int main(int argc, char* argv[]) {
	init_log();
	try {
		Client c;
		c.start();
		return 0;
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}
}