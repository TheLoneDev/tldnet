#ifndef _H_TEST_CONN_H
#define _H_TEST_CONN_H
#include <gtest/gtest.h>
#include <tldnet.h>
#include <thread>
#include <chrono>

using namespace tldnet;

TEST(connection, IPV4)
{
    SocketServer<IPVer::IPV4, Protocols::TCP, ListenScope::LOOPBACK> server(8080);
    ASSERT_TRUE(server.Create());
    ASSERT_TRUE(server.Bind());
    
    std::thread t([](){
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Wait for the server to listen, 500ms is exaggerated
        SocketClient<IPVer::IPV4, Protocols::TCP> clientSock(IPAddress<>(127,0,0,1), 8080);
        ASSERT_TRUE(clientSock.Create());
        ASSERT_TRUE(clientSock.Connect());
        
        std::array<uint8_t, 6> cliBuff = { 'H', 'e', 'l', 'l', 'o', 0};
        EXPECT_EQ(clientSock.Send(cliBuff.data(), cliBuff.size()), OpResult::OK);

        cliBuff = {};
        EXPECT_EQ(clientSock.Read(cliBuff.data(), cliBuff.size()), OpResult::OK);


    });

    auto client = server.Listen();
    EXPECT_TRUE(client.Initialized());

    std::array<uint8_t, 6> servBuff;
    EXPECT_EQ(client.Read(servBuff.data(), servBuff.size()), OpResult::OK);

    servBuff = { 'H', 'i', 0, 0, 0, 0};
    EXPECT_EQ(client.Send(servBuff.data(), servBuff.size()), OpResult::OK);
    

    t.join();
}

#endif