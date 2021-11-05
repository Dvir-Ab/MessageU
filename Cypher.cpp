#include "Cypher.h"

static MyCipher& getCipher(std::string filename)
{
	_cipher.init(filename);
	return _cipher;
}

void MyCipher::init(std::string filename) {
	if (!boost::filesystem::exists(filename + ".prv")) {
		CryptoPP::AutoSeededRandomPool asrp;
		CryptoPP::InvertibleRSAFunction priv_key;
		priv_key.Initialize(asrp, 1024);
		CryptoPP::HexEncoder priv_key_sink(new CryptoPP::FileSink((filename + ".prv").c_str()));

		priv_key.DEREncode(priv_key_sink);
		priv_key_sink.MessageEnd(); // call MessageEnd() to be called flush the buffer

		_pub_key = new CryptoPP::RSAFunction(priv_key);

		CryptoPP::HexEncoder pub_key_sink(new CryptoPP::FileSink((filename + ".pub").c_str()));
		_pub_key->DEREncode(pub_key_sink);
		pub_key_sink.MessageEnd();
	}
	else if (!boost::filesystem::exists(filename + ".pub")) {
		//error
		throw std::exception("Missing user's data files");
	}

}
//~MyCipher() {}


CryptoPP::byte* MyCipher::decrypt(const std::string& filename, const std::string& data) {
	try {
		CryptoPP::ByteQueue bq;
		CryptoPP::SecByteBlock ciperData(data.size());
		this->Load(filename, bq);
		CryptoPP::RandomNumberGenerator rnd;
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor;
		decryptor.AccessKey().Load(bq);
		decryptor.Decrypt(rnd, (CryptoPP::byte*)data.c_str(), data.size(), (CryptoPP::byte*)ciperData, decryptor.AccessKey());
		return ciperData.data();
	}
	catch (std::exception& e) {
		//log this exception
		throw std::exception(e);
	}
};

std::string MyCipher::encrypt_sym_with_pub(CryptoPP::byte* symmericKey, std::string pubKey) {
	CryptoPP::RandomNumberGenerator rng;
	CryptoPP::ByteQueue bq;
	CryptoPP::SecByteBlock cipherData;
	std::string cipherTxt;
	bq.Put(symmericKey, SYM_SIZE);
	bq.MessageEnd();
	CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor;
	encryptor.AccessKey().Load(bq);
	encryptor.Encrypt(rng, symmericKey, SYM_SIZE, cipherData);
	return std::string(cipherData.begin(), cipherData.end());
}

std::string MyCipher::encrypt_with_sym(CryptoPP::byte* symmericKey, const std::string& data) {
	// cbc encryptor
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };
	CryptoPP::AES::Encryption aesEnc(symmericKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEnc, iv);

	std::string cipherData;
	CryptoPP::StreamTransformationFilter encryptor(cbcEncryption, new CryptoPP::StringSink(cipherData));
	encryptor.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
	encryptor.MessageEnd(); // flush the ciphered data to std::string
	return cipherData;
}

std::string MyCipher::prepare(const std::string& fileName, const std::string& data) {
	//create an aes key
	CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };
	CryptoPP::AutoSeededRandomPool asrp;
	asrp.GenerateBlock(key, sizeof(key));
	//asrp.GenerateBlock(iv, sizeof(iv));
	std::string cipher, to_prepare_c(data);
	try {
		// cbc encryptor
		CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption enc;
		enc.SetKeyWithIV(key, sizeof(key), iv);

		// remove padding
		CryptoPP::StringSource s(to_prepare_c, true,
			new CryptoPP::StreamTransformationFilter(enc,
				new CryptoPP::StringSink(cipher)
			)
		);

		CryptoPP::StreamTransformationFilter filter(enc);
		filter.Put((const CryptoPP::byte*)to_prepare_c.data(), to_prepare_c.size());
		filter.MessageEnd();

		//CryptoPP::AutoSeededRandomPool asrp;
		//		CryptoPP::InvertibleRSAFunction priv_key;
		CryptoPP::ByteQueue bq;
		this->Load(fileName, bq);
		//	priv_key.Load(bq);//FileSource(this->PR_NAME,true,new CryptoPP::Base64Decoder()));

		CryptoPP::RSAFunction pub_key;
		bq.Clear();
		std::string in_buff;
		CryptoPP::FileSource file("me.info", true);
		std::istream* in = file.GetStream();
		std::getline(*in, in_buff, '\n');
		in_buff.clear();
		std::getline(*in, in_buff, '\n');
		pub_key.Load(bq);
	}
	catch (const CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
	}
};

CryptoPP::byte* MyCipher::new_sym_key() {
	CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	CryptoPP::AutoSeededRandomPool asrp;
	asrp.GenerateBlock(key, sizeof(key));
	return key;
}