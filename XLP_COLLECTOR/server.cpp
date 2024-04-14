#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h> 
#include <vector>
#include <ctime>
#include <fstream>
#include <chrono>


int main() {

    fd_set readfds;  
    std::vector<int>clientSockets; 
    std::vector<std::string>clientReads;

    // File Creation
    auto currentTimePoint = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(currentTimePoint);
    char timeStr[100];
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d_%H-%M-%S", std::localtime(&currentTime));
    std::string filename = "logs/" + std::string(timeStr) + ".txt";
    std::ofstream outputFile(filename, std::ofstream::out);

    // Create a socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return 1;
    }

    // Bind the socket to a specific port
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8086); // Port number 8086
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Listen on any available network interface

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error: Could not bind to port 8086" << std::endl;
        close(serverSocket);
        return 1;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 10) == -1) {
        std::cerr << "Error: Could not listen on port 8086" << std::endl;
        close(serverSocket);
        return 1;
    }

    std::cout << "Server is listening on port 8086..." << std::endl;

    char buffer[8192];

    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);   
        int max_fd = serverSocket;

        for(int clientSocket:clientSockets)
        {
            FD_SET( clientSocket , &readfds);
            max_fd = std::max(max_fd,clientSocket);
        }

        // std::cout << "Server is calling select " << max_fd << " " << std::endl;

        int chosen_fd =  select( max_fd + 1 , &readfds , NULL , NULL , NULL);   
        if(chosen_fd <0 && (errno != EINTR))
        {
            std::cerr << "Error: select call failure " << std::endl;
        }
        //std::cout << "Server is checking main socket" << std::endl;
        if (FD_ISSET(serverSocket, &readfds))   
        {
            std::cout << "Server is getting new accept connection " << std::endl;
            // Accept incoming connections
            struct sockaddr_in clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
            if (clientSocket == -1) {
                std::cerr << "Error: Could not accept incoming connection" << std::endl;
                close(serverSocket);
                return 1;
            }
            clientSockets.push_back(clientSocket);
            clientReads.push_back("");
        }

        for(int cl = 0; cl < clientSockets.size(); cl++)
        {
          int clientSocket = clientSockets[cl];
          //std::cout << "client Socket = " << clientSocket << std::endl;
          if(FD_ISSET(clientSocket, &readfds))
          {
            memset(buffer,0,sizeof(buffer));
            std::string& curr_log = clientReads[cl];
            ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            //std::cout << "Current timestamp: " << timeStr << std::endl;
            //std::cout << "Byte Recived = " << bytesReceived << std::endl;
            if (bytesReceived <= 0) {
                // std::cerr << "Error: Could not receive data from the client" << std::endl;
            } else {
                auto currentTime = std::chrono::system_clock::now();
                auto durationSinceEpoch = currentTime.time_since_epoch();
                auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(durationSinceEpoch);
                std::cout << "Epoch Time in milliseconds: " << milliseconds.count() << " milliseconds" << std::endl;
                for(int i=0; i<bytesReceived; i++)
                {
                    if(buffer[i]=='\n')
                    {
                        outputFile <<"Host "<<cl<<" : "<< curr_log << std::endl;
                        curr_log = "";
                    }
                    else 
                    {
                        curr_log+=buffer[i];
                    }
                }            
            }
          }
        }
    }

    close(serverSocket);
    for( int clientSocket:clientSockets)
        close(clientSocket);

    // // Accept incoming connections
    // struct sockaddr_in clientAddr;
    // socklen_t clientAddrLen = sizeof(clientAddr);
    // int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
    // if (clientSocket == -1) {
    //     std::cerr << "Error: Could not accept incoming connection" << std::endl;
    //     close(serverSocket);
    //     return 1;
    // }

    // std::cout << "Accepted a connection from " << inet_ntoa(clientAddr.sin_addr) << ":" << ntohs(clientAddr.sin_port) << std::endl;

    // char buffer[4096];
    // std::string curr_log = "";
    // // Receive and print the message from the client
    // while(1)
    // {
    //     memset(buffer,0,sizeof(buffer));
        
    //     ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    //     if (bytesReceived <= 0) {
    //         // std::cerr << "Error: Could not receive data from the client" << std::endl;
    //     } else {
    //         for(int i =0; i<bytesReceived; i++)
    //         {
    //             curr_log+=buffer[i];
    //             if(buffer[i]=='\n')
    //             {
    //                 std::cout << curr_log << std::endl;
    //                 curr_log = "";
    //             }
    //         }            
    //     }
    // }
    
    // // Close the sockets
    // close(clientSocket);
    // close(serverSocket);




    return 0;
}
