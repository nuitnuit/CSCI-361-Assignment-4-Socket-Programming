#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include <crypto++/files.h>
#include <crypto++/rsa.h>
#include <crypto++/secblock.h>
#include <cryptopp/osrng.h>
#include <crypto++/hex.h>
#include <cryptopp/idea.h>
#include <cryptopp/pssr.h>
#include <cryptopp/modes.h>

using namespace std;
using namespace CryptoPP;

//Note that if the length of the keys are changed here then the bytes read from socket
//must be changed accordingly as the ciphertext length is varied
const int SESSIONKEYLEN = IDEA::DEFAULT_KEYLENGTH, IVBLOCKLEN = IDEA::BLOCKSIZE;

//42.191.230.56
/*
    Lee Jun Lin 6664222
    IDEA has 128 bits key and 4 bits block size
    8 rounds with an extra round named as output transformation
    52 sub keys will be generated from 128 bits original key

    use 
    g++  -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o clientfolder/client clientfolder/client.cpp -lcryptopp
    to compile and run
    g++  -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o client client.cpp -lcryptopp
*/


int main()
{
    int sock = 0;
    sockaddr_in addr_info;
    string message, received = "";
    char buffer[2049] = {0};
    int PORT;
    string SERVERADDR;

    //setting up the socket connection

    
    do
    {
        cout << "Enter server port number" << endl;
        cin >> PORT;
        if (cin.bad() || !cin.good())
        {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            PORT = -1;
            cout << "Port number invalid" << endl;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    } while (PORT == -1);
    

    do
    {
        cout << "Enter server address" << endl;
        getline(cin, SERVERADDR);
        if (SERVERADDR == "")
        {
            cout << "Server address must not be empty" << endl;
        }
    } while (SERVERADDR == "");
    
    
    //creating socket
    cout << "Creating socket" << endl;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
   
    addr_info.sin_family = AF_INET; //IPv4
    addr_info.sin_port = htons(PORT); //set port number
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, (char*) SERVERADDR.c_str(), &addr_info.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    
    //connecting
    cout << "\nAttempting connection" << endl;
    int count = 0, status = 0;
    do
    {
        //attempt connect 4 times
        status = connect(sock, (struct sockaddr *)&addr_info, sizeof(addr_info));
        count++;
        if (status == 0)
        {
            break;
        }
    } while (count < 3);
    
    if (status == 0)
    {
        cout << "\nConnected to server" << endl;
        
        //generate RSA keys of size 3072 bits
        AutoSeededRandomPool prng; //rng
        InvertibleRSAFunction parameters; //object of n p q etc.
        parameters.GenerateRandomWithKeySize(prng, 3072); //generate privatekey
        RSA::PrivateKey privateKey(parameters); //assign
        RSA::PublicKey publicKey(parameters); //assign 


        //get public key string format
        string PUStr, PUhash, outputHex;
        StringSink transferPU(PUStr);
        ByteQueue sink;
        publicKey.Save(transferPU);


        //convert PUkey to hex format
        outputHex = "";
        StringSource(PUStr, true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nPublic key in hex: " << outputHex << endl;
        outputHex = "";

        //signing the PUkey using SHA1
        RSASS<PSS, SHA1>::Signer signer(privateKey);
        StringSource(PUStr, true, new SignerFilter(prng, signer, new StringSink(PUhash)));

        
        //convert to hex format
        outputHex = "";
        StringSource(PUhash, true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nPublic key hash in hex: " << outputHex << endl;
        outputHex = "";


        cout << "\nSending public key concatenated with hash of public key" << endl;
        //PUStr send over with Hsha1(PUStr) to server
        message = PUStr + PUhash;
        int status = send(sock, message.c_str(), message.length(), 0);
        if (status == -1)
        {
            cout << "\nSending unsuccessful\n" << endl;
            close(sock);
            return 1;
        }
        else
        {
            cout << "\nPublic key sent to server\n" << endl;
        }

        //getting the session key and iv and hashes from server
        //server will send the key and key hash
        //then send the iv and iv hash
        RSAES_PKCS1v15_Decryptor decryptor(privateKey); //decryptor for the IDEA session key and IV


        string PUSessionKey, sessionKeyStr, keyHash, ivStr, ivHash, PUivStr;
        bool result1, result2; //holds the result for the hash verification
        SHA1 hasher; //hasher object to verify the hash later


        //get the session key and store it temporarily
        read(sock, buffer, 404);
        received = "";
        for(int i = 0; i < 404; i++)
        {
            received += buffer[i];
        }

        cout << "\nReceived session key from server\n" << endl;
        StringSource getSessionKey(received, false, new StringSink(PUSessionKey));
        getSessionKey.Pump(384);
        getSessionKey.Attach(new StringSink(keyHash)); //key key hash
        getSessionKey.PumpAll();


        //output encrypted session key in hex
        StringSource(PUSessionKey, true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nSession key encrypted with PUkey: " << outputHex << endl;
        outputHex = "";


        //decrypt the idea session key and store into sessionKeyStr
        StringSource(PUSessionKey, true, 
            new PK_DecryptorFilter(prng, decryptor, new StringSink(sessionKeyStr))
        ); 


        //output key in hex
        StringSource(sessionKeyStr, true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nIDEA session key in hex: " << outputHex << endl;
        outputHex = "";
        StringSource(keyHash, true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nIDEA session key hash in hex: " << outputHex << endl;
        outputHex = "";


        //verify the hash of sessionkey and output the result to result1
        //tells hashverificationfilter to throw exception on error and
        //the hash is concatenated at the back
        const int verificationFlags = HashVerificationFilter::HASH_AT_END;
        
        
        
        //verify the session key
        //hash dunno why put at back got issue but not infront.
        //putting hash in front for now until further solutions found
        StringSource(keyHash + sessionKeyStr, true, new HashVerificationFilter(hasher, 
            new ArraySink((byte*) &result1, sizeof(result1)))
        );


        //get the iv and iv hash and store it
        read(sock, buffer, 404);
        received = "";
        for(int i = 0; i < 404; i++)
        {
            received += buffer[i];
        }


        StringSource getIV(received, false, new StringSink(PUivStr));
        getIV.Pump(384);
        getIV.Attach(new StringSink(ivHash));
        getIV.PumpAll();

        StringSource(PUivStr, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(ivStr)));


        //output iv in hex
        StringSource(ivStr, true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nIDEA IV in hex: " << outputHex << endl;
        outputHex = "";
        StringSource(ivHash, true, new HexEncoder(new StringSink(outputHex)));
        cout << "\nIDEA IV hash in hex: " << outputHex << endl;
        outputHex = "";
        

        //verify the hash of iv and output the result to result2
        StringSource(ivHash + ivStr, true, new HashVerificationFilter(hasher, 
            new ArraySink((byte*) &result2, sizeof(result2)))
        );

        if (result1 == true && result2 == true)
        {

            cout << "\nBoth IDEA session key and IV are verified and genuine.\n"
            << "Switching over to IDEA session key to communicate with server\n" << endl;


            SecByteBlock sessionKey(SESSIONKEYLEN); //allocate 16 byte for IDEA key
            byte iv[IVBLOCKLEN]; //allocate 8 bytes for iv
            //assign session key
            sessionKey.Assign(reinterpret_cast<const byte*>(&sessionKeyStr[0]), sessionKeyStr.size());
            for(int i = 0; i < ivStr.length(); i++)
            {
                iv[i] = ivStr[i];
            }

            CFB_Mode<IDEA>::Encryption encryptIDEA;
            CFB_Mode<IDEA>::Decryption decryptIDEA;
            encryptIDEA.SetKeyWithIV(sessionKey, sessionKey.size(), iv);
            decryptIDEA.SetKeyWithIV(sessionKey, sessionKey.size(), iv);
            cout << "\nChat program starting up...\nPress CTRL + C to terminate or type in \\\\0." << endl;
            
            
            while(1)
            {
                string temp = "", k, output = "";

                message = "";
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
                        status = send(sock, k.c_str(), k.length(), 0);
                    }
                    else
                    {
                        k = temp;
                        temp = "";
                    }
                    status = send(sock, k.c_str(), k.length(), 0);
                } while (temp.length() > 0);
                if (message == "\\\\0")
                {
                    close(sock);
                    cout << "Connection closed" << endl;
                    break;
                }
                else if(status < 0)
                {
                    cout << "\nError while trying to send." << endl;
                }
                temp = "";
                message = "";


                do//this block will read as many times as needed
                {
                    bzero(buffer, 2049);//clear buffer
                    status = read(sock, buffer, 2049);
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
                    cout << "\nServer: " << output << endl;
                }
                else
                {
                    cout << "Server closed connection." << endl;
                    close(sock);
                    break;
                }
                //clear output string and buffer
                bzero(buffer, 2049);
                output = temp = "";
            }
        }
        else
        {
            cout << "\nVerification status:"
            << "\nIDEA session key: " << (result1 ? "Verified" : "Failed")
            << "\nIV: " << (result2 ? "Verified" : "Failed") << endl;
            close(sock);
        }
    }        
    else
    {
        cout << "\nConnection failed. Is the server up?" << endl;
    }  
    return 0;
}
