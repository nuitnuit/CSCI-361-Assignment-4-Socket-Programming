// Client side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#define PORT 9999
//42.191.230.56

using namespace std;

int main(int argc, char const *argv[])
{
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	string hello = "Hello from client";
	char buffer[1024] = {0};
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}
    cout << "Socket created" << endl;

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, "42.191.230.56", &serv_addr.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}
    cout << "Address converted" << endl;

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
    cout << "Connection established" << endl;
	while(1)
	{
		bzero(buffer, 1024);
		fgets(buffer, 1024, stdin);
		int n = send(sock , buffer, strlen(buffer), 0);
		cout << n << endl;	

		bzero(buffer, 1024);
		valread = read(sock, buffer, 1024);
		printf("\nServer: %s", buffer); 	
	}
    close(sock);
	return 0;
}