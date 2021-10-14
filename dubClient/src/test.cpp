// before make: g++ test.cpp -L:$(pwd)/.. -l:libcryptopp.a -g -o out

#include<iostream>
#include<string>
#include<cstring>
#include"../header/fmt/format.h"
#include"../header/crypto/cryptlib.h"
#include"../header/crypto/rijndael.h"
#include"../header/crypto/modes.h"
#include"../header/crypto/files.h"
#include"../header/crypto/osrng.h"
#include"../header/crypto/hex.h"
#include"../header/crypto/rsa.h"



void Encode(const std::string&, const CryptoPP::BufferedTransformation&);
void EncodePrivKey(const std::string&, const CryptoPP::RSA::PrivateKey&);
void EncodePubKey(const std::string&,const CryptoPP::BufferedTransformation&);

int main(int argc, char** argv)
{
    using namespace CryptoPP;

    if(argc != 2)
    {
        std::cout << fmt::format("Ok Okay, not one argument \n");
    }else{
        std::cout << fmt::format("Exactly one argument \n");
    }
    // Key Generation
    AutoSeededRandomPool rng;
    
    //RSA Key Generation
    RSA::PrivateKey private_RSA_key;

    try{
        private_RSA_key.GenerateRandomWithKeySize(rng, 3072);
        RSA::PublicKey public_RSA_key(private_RSA_key);
        
    } catch(const CryptoPP::Exception& CRYPT_E)
    {
        std::cout << "What: " + CRYPT_E.GetWhat() << std::endl;
        return -1;
    }
    
    
}

void Encode(const std::string& filename, const CryptoPP::BufferedTransformation& bt)
{
    
    CryptoPP::FileSink file(filename.c_str());
    
    bt.CopyTo(file);
    file.MessageEnd();
}

void EncodePrivKey(const std::string& filename, const CryptoPP::RSA::PrivateKey& key)
{
    CryptoPP::ByteQueue queue;
    key.DEREncodePrivateKey(queue);

    Encode(filename, queue);
}

void EncodePubKey(const std::string& filename, const CryptoPP::RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;
    key.DEREncodePublicKey(queue);
    
    Encode(filename, queue);
}
