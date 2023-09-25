#ifndef _H_TEST_ADDR_H
#define _H_TEST_ADDR_H
#include <gtest/gtest.h>
#include <tldnet.h>
#include <sstream>

using namespace tldnet;

TEST(Addresses, MAC)
{
    MACAddr mac(0x25,0x26,0x27,0x28,0x29,0x30);
    ASSERT_EQ(mac.GetAddressPrimitive()[0], 0x252627282930);
}

TEST(Addresses, IPV4)
{
    IPAddress<IPVer::IPV4> ipv4(192,168,69,42);
    ASSERT_EQ(ipv4.GetAddressPrimitive()[0], 0x2A45A8C0);

    IPAddress<IPVer::IPV4> ipv4Str("192.168.69.42");
    std::stringstream hexStream;
    hexStream << std::hex << ipv4Str.GetAddressPrimitive()[0];
    ASSERT_EQ(ipv4Str.GetAddressPrimitive()[0], 0x2A45A8C0) << "Got:" << hexStream.str();
}

#endif