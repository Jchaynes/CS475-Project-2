// before make: g++ test.cpp -L:$(pwd)/.. -l:libcryptopp.a -g -o out

#include<iostream>
#include<string>
#include<cstring>
#include<fstream>
#include<signal.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<cstdint>
#include<netdb.h>
#include <unistd.h>
#include"../header/fmt/format.h"
#include"../header/crypto/cryptlib.h"
#include"../header/crypto/rijndael.h"
#include"../header/crypto/modes.h"
#include"../header/crypto/files.h"
#include"../header/crypto/filters.h"
#include"../header/crypto/osrng.h"
#include"../header/crypto/hex.h"
#include"../header/crypto/rsa.h"
#include"../header/crypto/pem.h"

using namespace CryptoPP;

// void Save(const std::string& filename, const BufferedTransformation& bt);

int main(int argc, char** argv)
{

    if(argc != 2)
    {
        std::cout << fmt::format("Invalid arguments: {0} [PORT] \n",argv[0]);
        return -1;
    }

    // Key Generation
    AutoSeededRandomPool rng;
    unsigned int bitties = 3072;
    //RSA Key Generation
    RSAES_OAEP_SHA_Decryptor rsaPrivateKey;
    rsaPrivateKey.AccessKey().GenerateRandomWithKeySize(rng, bitties);
    RSAES_OAEP_SHA_Encryptor rsaPublicKey(rsaPrivateKey);

    // try{
    //     rsaPrivateKey.AccessKey().GenerateRandomWithKeySize(rng, bitties);
    // } catch(const CryptoPP::Exception& CRYPT_E)
    // {
    //     std::cout << "What: " + CRYPT_E.GetWhat() << std::endl;
    //     return -1;
    // }

    
    // EncodePrivKey("rsa-private.key",private_RSA_key);
    // EncodePubKey("rsa-pub.key",public_RSA_key);
    
    // establish network connection
    std::string sop = "isoptera.lcsc.edu";
    struct sockaddr_in sai;
    struct hostent *ent;
    struct in_addr **addr_list;
    sai.sin_family = AF_INET;

    char *p;
    long port = strtol(argv[1],&p, 10);
    sai.sin_port = htons(port);
    
    int skt = -1;
    
    skt = socket(sai.sin_family,SOCK_STREAM,0);
    if(skt == -1)
    {
        perror("Unable to establish socket");
        return -1;
    } else {std::cout << fmt::format("Socket seemed to establish!\n");}

    //resolve isoptera
    if((ent = gethostbyname(sop.c_str() ) ) == NULL)
    {
        herror("gethostbyname");
        std::cout << fmt::format("Failed to resolve domain\n");
        return -1;
    }

    addr_list = reinterpret_cast<struct in_addr**>(ent->h_addr_list);

    for(int i = 0; addr_list[i] != NULL; i++)
    {
        sai.sin_addr = *addr_list[i];
    }
    std::cout << fmt::format("{0} resolved to: {1}\n",sop,inet_ntoa(sai.sin_addr));

    //try connection
    // if(connect(skt, reinterpret_cast<struct sockaddr*>(&sai), sizeof(sai)) < 0)
    // {
    //     perror("Remote connection failed.");
    //     return -1;
    // }
    std::cout << fmt::format("Successfully connected.\n");

    /*-------------------------------------------------------------
                        CONNECTION ESTABLISHED
    
        1. Server listens on port
        2. Client connects to port
        3. Client sends public RSA key (4 bytes unsigned)
        4. Server generates AES session key (16 bytes unsigned)
        5. Server encrypts AES key with RSA key
        6. Server sends encrypted key to client and waits
        7. Client decrypts session key
        8. Client encrypts either hardcoded string or user input with session key (Send length first, up to 4 bytes unsigned)
        9. Client sends message to confirm receipt and decryption of key (Send length first, up to 4 bytes unsigned)
        10. Server decrypts message from client with session key
        11. Server sends hardcoded or user input message encrypted with session key
    -------------------------------------------------------------*/
    ssize_t bytes = 0;
    char* outgoing;
    ssize_t remain_to_send = 0;
    ssize_t amount_sent = 0;
    
    // save a PEM and load it (with PEM pack) consider DER/Base64 if more sane solution
    FileSink phial("RSA_priv.pem",true);
    CryptoPP::PEM_Save(phial,rsaPrivateKey.GetKey());
    
    

}

// void Save(const std::string& filename, const BufferedTransformation& bt)
// {
//     FileSink file(filename.c_str());
//     bt.CopyTo(file);
//     file.MessageEnd();
// }

