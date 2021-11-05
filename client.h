#include "Header.h"

namespace CLIENT
{
	class Client {
	private:
		std::string readInput();
		void loadSelfInfo();

		FriendsManager _fm;
		std::string _host, _port;
	public:
		Client() : _fm() {
			try
			{	// tring  to read the server info
				boost::filesystem::ifstream input;
				input.open("server.info");
				if (!std::getline(input, this->_host, ':')) throw std::exception("Error: the host\'s address in the file: \'server.info\' is not right.");
				if (!std::getline(input, this->_port)) throw std::exception("Error: the port in the file: \'server.info\' is not right.");
				input.close();

				this->loadSelfInfo();
			}
			catch (const std::exception& e) {
				std::cerr << e.what() << "\nClient constructor failed" << std::endl;
			}
		};

		void interact();
		void handleResponse();
		void start();

	};
} // end of namespace __CLIENT__