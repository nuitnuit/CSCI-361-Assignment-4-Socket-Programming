#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#include <cryptopp/files.h>
#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/idea.h>
#include <cryptopp/hex.h>
#include <cryptopp/pssr.h>
#include <cryptopp/modes.h>

using namespace std;
using namespace CryptoPP;

const int SESSIONKEYLEN = IDEA::DEFAULT_KEYLENGTH, IVBLOCKLEN = IDEA::BLOCKSIZE;

/*
    Lee Jun Lin 6664222
    IDEA has 128 bits key and 4 bits block size
    8 rounds with an extra round named as output transformation
    52 sub keys will be generated from 128 bits original key
    
    use 
    g++  -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o serverfolder/server serverfolder/server.cpp -lcryptopp
    to compile and run

    
*/


int main()
{
    int fd_socket, new_socket, status;
    sockaddr_in addr_info;
    int options = 1;
    int addrlen = sizeof(addr_info);
    int PORT;
    char buffer[2049] = {0};//initialize 2049 size buffer
    string received = "";
    string message;


    //get port number
    do
    {
        cout << "Enter port number to host" << endl;
        cin >> PORT;
    } while (PORT == NULL || PORT < 0 || PORT > 65535);

    
    // Creating socket file descriptor
    if ((fd_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Forcefully attaching socket to the port 
    if (setsockopt(fd_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &options, sizeof(options)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    addr_info.sin_family = AF_INET;
    addr_info.sin_addr.s_addr = INADDR_ANY;
    addr_info.sin_port = htons(PORT);

    // Forcefully attaching socket to the port
    if (bind(fd_socket, (struct sockaddr *)&addr_info, sizeof(addr_info))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    //listen for connection from client
    cout << "\nListening for client to connect" << endl;
    if (listen(fd_socket, 3) < 0)
    {
        perror("Error at setting connection to passive mode");
        exit(EXIT_FAILURE);
    }


    //accept connection
    if ((new_socket = accept(fd_socket, (struct sockaddr *) &addr_info, (socklen_t*) &addrlen))<0)
    {
        perror("Error at accepting connection");
        exit(EXIT_FAILURE);
    }
    
    
    cout << "\nConnection accepted." << endl;
    cout << "Socket setup done. Waiting for client to send PUkey\n" << endl;


    //receive PUkey with hash
    status = read(new_socket, buffer, 804);
    cout << "\nPUkey received from client. Performing validation.\n" << endl;
    received = "";
    for(int i = 0; i < 804; i++)
    {
        received += buffer[i];
    }


    string outputHex, PUhash, PUkey;
    //get PUkey
    //get 3072 bits PUkey
    StringSource PUpump(received, false, new StringSink(PUkey));
    PUpump.Pump(420);

    //get hash of PUkey
    PUpump.Attach(new StringSink(PUhash));
    PUpump.PumpAll();

    //display hex of PUkey
    outputHex = "";
    StringSource(PUkey, true, new HexEncoder(new StringSink(outputHex)));
    cout << "\nClient's public key in hex: " << outputHex << endl;


    //display hex of hash of PUkey
    outputHex = "";
    StringSource(PUhash, true, new HexEncoder(new StringSink(outputHex)));
    cout << "\nClient's PUkey hash is: " << outputHex << endl;

    //confirm the PUkey authenticity
    RSA::PublicKey publicKey;
    StringSource getPUkey(PUkey, true);
    publicKey.Load(getPUkey);


    //create verifier object
    RSASS<PSS, SHA1>::Verifier verifier(publicKey);
    //PSS is probabilistic signature scheme
    
    //verify the signature
    bool result = verifier.VerifyMessage((const byte*) PUkey.c_str(), PUkey.length(), 
        (const byte*) PUhash.c_str(), PUhash.size());

    if (result == true)
    {
        cout << "\nVerification is successful. The signature is genuine.\n"
        << "Server will now prepare IDEA session key for client.\n" << endl;


        //encryptor object using client's public key
        //this will be used to encrypt the IDEA session key
        RSAES_PKCS1v15_Encryptor encryptor(publicKey);


        //SHA1 hasher
        SHA1 hasher;


        //generate IDEA key
        //start prepare IDEA key and send it
        string ivHash, keyHash, PUSessionKey, PUiv;
        SecByteBlock sessionKey(SESSIONKEYLEN); //create a key of size 16 bytes
        byte iv[IVBLOCKLEN]; //create iv of size 8 bytes
        AutoSeededRandomPool prng;
        string sessionKeyStr;
        prng.GenerateBlock(sessionKey, sessionKey.size());
        prng.GenerateBlock(iv, sizeof(iv));
        StringSource(reinterpret_cast<const char*>(&sessionKey[0]), true, new StringSink(sessionKeyStr));


        //sign the key and iv
        StringSource(sessionKeyStr, true, new HashFilter(hasher, new StringSink(keyHash)));
        StringSource(reinterpret_cast<char*>(&iv[0]), true, new HashFilter(hasher, new StringSink(ivHash)));


        //encrypt the key and iv
        StringSource(sessionKeyStr, true, 
            new PK_EncryptorFilter(prng, encryptor, new StringSink(PUSessionKey))
        );
        

        StringSource(reinterpret_cast<char*>(&iv[0]), true, 
            new PK_EncryptorFilter(prng, encryptor, new StringSink(PUiv))
        );


        //display session key 
        outputHex = "";
        StringSource(sessionKeyStr, true, new HexEncoder(new StringSink(outputHex)));
        cout << "Generated IDEA session key: " << outputHex << endl;
        outputHex = "";
        StringSource(PUSessionKey, true, new HexEncoder(new StringSink(outputHex)));
        cout << "IDEA session key encrypted with client's PUkey: " << outputHex << endl;
        outputHex = "";
        StringSource(keyHash, true, new HexEncoder(new StringSink(outputHex)));
        cout << "IDEA session key hashed with SHA1: " << outputHex << endl;


        //iv display
        outputHex = "";
        StringSource(reinterpret_cast<char*>(&iv[0]), true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nIV generated: " << outputHex << endl;
        outputHex = "";
        StringSource(PUiv, true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nIV encrypted with client's PUkey: " << outputHex << endl;
        outputHex = "";
        StringSource(ivHash, true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nIV hash using SHA1: " << outputHex << endl;
        outputHex = "";


        //send IDEA key concatenate with hash encrypted using PUkey and SHA1
        message = PUSessionKey + keyHash;
        send(new_socket, message.c_str(), message.length(), 0);
        cout << "\nIDEA session key sent encrypted with PUkey, concatenated with SHA1 hash\n" << endl;

        //send iv concatenate with hash encrypted using PUkey and SHA1
        message = PUiv + ivHash;


        //this is for future debugging purpose
        //cout << PUiv.length() << endl << ivHash.length() << endl;


        send(new_socket, (char*) message.c_str(), message.length(), 0);
        cout << "\nIDEA IV sent encrypted with PUkey, concatenated with SHA1 hash\n" << endl;


        //this is for future debugging purpose
        //cout << message.length() << endl;


        cout << "\nIDEA key and IV sent with their respective hashes\n" << endl;
        cout << "\nServer will now use session key to communicate with client\n" << endl;


        CFB_Mode<IDEA>::Encryption encryptIDEA;
        CFB_Mode<IDEA>::Decryption decryptIDEA;
        encryptIDEA.SetKeyWithIV(sessionKey, sessionKey.size(), iv);
        decryptIDEA.SetKeyWithIV(sessionKey, sessionKey.size(), iv);
        cout << "\nChat program starting up...\nPress CTRL + C to terminate or type in \\\\0." << endl;
        
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        while(1)
        {
            string temp = "", k, output = "";

            //this block will read as many times as needed
            //this block is still flawed as if the sender sent 2049
            //bytes then it will be trapped here
            //but since the message will be sent in an encrypted manner,
            //the ciphertext length is not likely to be an odd number
            do
            {
                bzero(buffer, 2049);//clear buffer
                status = read(new_socket, buffer, 2049);
                if(status < 0)
                {
                    cout << "\nError while trying to read." << endl;
                }
                else if (status == 0)
                {
                    break;
                }
                else
                {
                    temp += buffer;
                }
            } while (status == 2049);

            StringSource(temp, true, 
                new StreamTransformationFilter(decryptIDEA, new StringSink(output))
            );//decrypt the message using session key
            if (output != "\\\\0")
            {
                cout << "\nClient: " << output << endl;
            }
            else
            {
                cout << "Client closed connection." << endl;
                close(new_socket);
                close(fd_socket);
                break;
            }
            //clear output string and buffer
            bzero(buffer, 2049);
            output = temp = "";


            //sending message
            cout << ">";
            getline(cin, message);

            StringSource(message, true, 
                new StreamTransformationFilter(encryptIDEA, new StringSink(temp))
            );//encrypt the message using session key
            
            do
            {
                if (temp.length() > 2048)
                {
                    k = temp.substr(0, 2047);//get first 2048 bytes
                    temp = temp.substr(2048);//subtract off first 2048 bytes
                }
                else if (temp.length() == 2048) //this will send twice for when 2049 bytes read by receipient
                {
                    k = temp;
                    temp = "";
                    status = send(new_socket, k.c_str(), k.length(), 0);
                }
                else
                {
                    k = temp;
                    temp = "";
                }
                status = send(new_socket, k.c_str(), k.length(), 0);
            } while (temp.length() > 0);
            if (message == "\\\\0")
            {
                close(new_socket);
                close(fd_socket);
                cout << "Connection closed" << endl;
                break;
            }
            else if(status < 0)
            {
                cout << "\nError while trying to send." << endl;
            }
            temp = message = "";
        }
    }
    else
    {
        cout << "\nVerification is unsuccessful. Program will terminate and close the connection.\n" 
        << endl;
        close(new_socket);
        close(fd_socket);
    }
    return 0;
}
