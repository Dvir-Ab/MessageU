
#include "client.h"



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