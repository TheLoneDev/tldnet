#ifndef _H_TLDNET_H
#define _H_TLDNET_H

#ifdef __linux
    #ifdef __ANDROID__
        #define PLATFORM_ANDROID 1
    #else
        #define PLATFORM_LINUX 1
    #endif
#elif defined(_WIN32)
    #define PLATFORM_WINDOWS 1
#elif defined(__APPLE__)
    #define PLATFORM_APPLE 1
    #ifdef TARGET_OS_OSX
        #define PLATFORM_MACOS 1
    #elif defined(TARGET_OS_IPHONE)
        #define PLATFORM_IOS 1
    #endif
#elif defined(unix)
    #define PLATFORM_UNIX 1
#else
    #error Platform unsupported 
#endif

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string>
#include <string.h>
#include <iostream>
#include <ostream>
#include <array>
#include <algorithm>
#if PLATFORM_LINUX || PLATFORM_APPLE || PLATFORM_UNIX
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#elif PLATFORM_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#if defined(_MSC_VER) && !NO_WS2_LINK
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#endif
#else
#error This platform is unsupported
#endif

namespace tldnet
{
//////////////////////////////
/* Consts and stuff*/
//////////////////////////////
    constexpr static int HOST_MAX_LENGTH = 64;
//////////////////////////////
/* Classes and definitions */
//////////////////////////////
    namespace exceptions
    {
        enum class SocketError
        {
            NULL_SOCKET, FAILED_SEND, FAILED_READ
        };

        template<SocketError SOCK_ERROR>
        class SocketException : public std::runtime_error{};

        template<>
        class SocketException<SocketError::NULL_SOCKET> : public std::runtime_error
        {
        public:
            SocketException() : std::runtime_error("Socket file descriptor is null"){};
        };

        template<>
        class SocketException<SocketError::FAILED_SEND> : public std::runtime_error
        {
        public:
            SocketException() : std::runtime_error("Failed to send data via socket"){};
        };

        template<>
        class SocketException<SocketError::FAILED_READ> : public std::runtime_error
        {
        public:
            SocketException() : std::runtime_error("Failed to read data via socket"){};
        };

        class StringEmpty : public std::runtime_error
        {
        public:
            StringEmpty() : std::runtime_error("String is empty"){};
        };
    }

    enum class Protocols // These are built-in protocols in the supported OSes
    {
        TCP, UDP, ICMP, RAW, // Consider adding GRE, PUP, MPLS in the future
    };

    enum class IPVer // Internet Protocol version (version 4 || version 6)
    {
        IPV4 = AF_INET, IPV6 = AF_INET6, ANY = AF_UNSPEC
    };

    enum class ListenScope // What scope to listen to
    {                      // TODO: Change this concept to custom address
        ALL, LOOPBACK 
    };

    enum class OpResult
    {
        FAILED, // When an operation failed
        OK,      // Succeeded, but there is probably more data to handle
        END    // When it succeeded, but ended (e.g. no more data)
    };  

// #pragma pack(1)
    template<typename T, std::size_t SIZE>
    class Data
    {
    public:
        inline constexpr void Set(std::size_t index, T val) { m_Data[index] = val; };
        inline constexpr T& Get(std::size_t index) { return m_Data[index]; };
        inline constexpr T& operator[](std::size_t index) { return m_Data[index]; };

        template<typename SUBT>
        inline constexpr SUBT& GetAs(std::size_t index) { return reinterpret_cast<SUBT*>(m_Data)[index]; };

        inline T* GetPtr() { return m_Data; };
        inline constexpr std::size_t GetSize() { return m_Size; };
        inline constexpr std::size_t GetSizeBytes() { return GetSize() * sizeof(T); };

    private:
        alignas(sizeof(T)*SIZE > alignof(std::max_align_t) ? alignof(std::max_align_t) : sizeof(T)*SIZE)
        T m_Data[SIZE] = {};
        constexpr static std::size_t m_Size = SIZE;
    };
// #pragma pack()

    template<typename ADDR_TYPE, std::size_t ADDR_SIZE>
    class Address
    {
    public:
        inline constexpr bool IsValid() const { return m_Valid; };
        inline constexpr void SetValid(bool b) { m_Valid = b; };
        inline tldnet::Data<ADDR_TYPE, ADDR_SIZE>& GetAddressPrimitive() { return m_Address; }; // Intellisenses get confused here, so I am not using auto&
    protected:
        tldnet::Data<ADDR_TYPE, ADDR_SIZE> m_Address = {}; // Reset to 0 reserve constexpr
        bool m_Valid = false; // If address parsed successfully (used for strings)
    };

    class MACAddr : public Address<uint64_t, 1>
    {
    public:
        constexpr MACAddr(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);
    };

    class Host
    {
    public:
        constexpr Host(const char* hostname);
    public:
        const auto& GetHostname() { return m_Hostname; };
    private:
        std::array<char, HOST_MAX_LENGTH> m_Hostname = {}; // Reset for constexperability
    };


    template<IPVer IPVER = IPVer::IPV4>
    class IPAddress;

    template<>
    class IPAddress<IPVer::IPV4> : public Address<uint32_t, 1>
    {
    public:
        constexpr IPAddress(const char* ipStr); // Translate string to network bytes (e.g. "192.168.69.42")
        constexpr IPAddress(uint8_t a = 0, uint8_t b = 0, uint8_t c = 0, uint8_t d = 0); // Translate 4 bytes to 32bit network-byte order address
        IPAddress(Host host); // Translate a host
    private:
        IPVer m_Ver = IPVer::IPV4; // Initialize for constexpr constructor
    };

    template<>
    class IPAddress<IPVer::IPV6> : public Address<uint64_t, 2>
    {
    public:
        constexpr IPAddress(const char* ipStr); // Translate string to network bytes (e.g. "2a00:1450:4028:809::200e")
        constexpr IPAddress(uint16_t a = 0, uint16_t b = 0, uint16_t c = 0, uint16_t d = 0, uint16_t e = 0, uint16_t f = 0, uint16_t g = 0, uint16_t h = 0); // IPV6 bytes
        IPAddress(Host host); // Translate a host
    private:
        IPVer m_Ver = IPVer::IPV6;
    };

    template<IPVer IPVER, Protocols PROTOCOL>
    class SocketBase
    {
    public:
        SocketBase(uint16_t port = 0) { SetPort(port); };
        ~SocketBase();
    public:
        inline constexpr void SetPort(uint16_t port) { m_Port = port; };
        inline uint16_t GetPort() const { return m_Port; };
        inline int GetSocketFD() const { return m_Socket; };
        inline void SetSocketFD(int fd) { m_Socket = fd; };
        inline bool Initialized() const { return static_cast<bool>(m_Socket); };
        inline constexpr void SetTimeout(int timeout) { m_Timeout = timeout; };
        inline int GetTimeout() const { return m_Timeout; };
        inline bool IsTimeoutSet() const { return m_Timeout != INT_MAX; };
        inline constexpr void SetTTL (int ttl) { if (ttl <= 255 && ttl >= 0)m_TTL = ttl; };
        inline int GetTTL() const { return m_TTL; };
        inline bool IsTTLSet() const { return m_TTL != INT_MAX; };
        inline constexpr void EnableBroadcast(bool b) { m_BroadcastEnabled = b; };
        inline bool IsBroadcastEnabled() const { return m_BroadcastEnabled; };
    public:
        bool Init();
        OpResult Send(const uint8_t* data, std::size_t nBytes);
        inline OpResult Send(const char* str, std::size_t nBytes) { return Send(reinterpret_cast<const uint8_t*>(str), nBytes); };
        OpResult Read(uint8_t* buffer, std::size_t nBytes);
        
        template<typename BUFFTYPE, std::size_t BUFFSIZE>
        SocketBase& operator<<(std::array<BUFFTYPE, BUFFSIZE>& arr);
        SocketBase& operator<<(const std::string& str);
        SocketBase& operator<<(const char* str);
        
        template<typename BUFFTYPE, std::size_t BUFFSIZE>
        SocketBase& operator>>(std::array<BUFFTYPE, BUFFSIZE>& arr);
        SocketBase& operator>>(std::string& str);
    protected:
        uint16_t m_Port;
        int m_Timeout = INT_MAX; // Connection timeout (ms)
        int m_TTL = INT_MAX; // not uint8_t to mark when to skip (bigger value than uint8) and 32bit is faster to load (two birds)
        bool m_BroadcastEnabled = false;
        int m_Socket = 0;
    };

    template<IPVer IPVER, Protocols PROTOCOL>
    class Socket;

    template<Protocols PROTOCOL>
    class Socket<IPVer::IPV4, PROTOCOL> : public SocketBase<IPVer::IPV4, PROTOCOL>
    {
    public:
        Socket(uint16_t port = 0) : SocketBase<IPVer::IPV4, PROTOCOL>(port) {};

        template<typename BUFFTYPE, std::size_t BUFFSIZE>
        Socket<IPVer::IPV4, PROTOCOL>& operator<<(std::array<BUFFTYPE, BUFFSIZE>& arr) { (void)SocketBase<IPVer::IPV4, PROTOCOL>::operator<<(arr); return *this;};

        Socket<IPVer::IPV4, PROTOCOL>& operator<<(const std::string& str) { (void)SocketBase<IPVer::IPV4, PROTOCOL>::operator<<(str); return *this; };
    protected:
        sockaddr_in m_SockAddrIn = {};
    };

    template<Protocols PROTOCOL>
    class Socket<IPVer::IPV6, PROTOCOL> : public SocketBase<IPVer::IPV6, PROTOCOL>
    {
    public:
        Socket(uint16_t port = 0) : SocketBase<IPVer::IPV6, PROTOCOL>(port) {};

        template<typename BUFFTYPE, std::size_t BUFFSIZE>
        Socket<IPVer::IPV6, PROTOCOL>& operator<<(std::array<BUFFTYPE, BUFFSIZE>& arr) { (void)SocketBase<IPVer::IPV6, PROTOCOL>::operator<<(arr); return *this;};
        Socket<IPVer::IPV6, PROTOCOL>& operator<<(const std::string& str) { (void)SocketBase<IPVer::IPV6, PROTOCOL>::operator<<(str); return *this; };
    protected:
        sockaddr_in6 m_SockAddrIn = {};
    };

    // BUFF_SIZE is a future implement. Currently could be totally ignored.
    template<IPVer IPVER, Protocols PROTOCOL, std::size_t BUFF_SIZE = 1024>
    class SocketClient : public Socket<IPVER, PROTOCOL>
    {
    public:
        //SocketClient(std::string host, uint16_t port = 0) : Socket<IPVER, PROTOCOL>(port) { SetHost(host); };
        SocketClient(IPAddress<IPVER> addr, uint16_t port = 0) : Socket<IPVER, PROTOCOL>(port) { SetAddr(addr); };
        bool Create();
        bool Connect();
    public:
        inline void SetAddr(IPAddress<IPVER> addr) { m_Addr = addr; };
        inline std::string GetAddr() { return m_Addr; };
    private:
        IPAddress<IPVER> m_Addr;
    };
    
    // BUFF_SIZE is a future implement. Currently could be totally ignored.
    template<IPVer IPVER, Protocols PROTOCOL, ListenScope LISTEN_SCOPE = ListenScope::ALL, std::size_t BUFF_SIZE = 1024>
    class SocketServer : public Socket<IPVER, PROTOCOL>
    {
    public:
        SocketServer(uint16_t port = 0) : Socket<IPVER, PROTOCOL>(port) {};
        bool Create();
        bool Bind();
        Socket<IPVER, PROTOCOL> Listen();
        void HandleSockets();
    private:
    }; 
}
/////////////////////////////////////
/* Functions and implementations */
//////////////////////////////

namespace tldnet
{

    // This is strlne() implementation to achieve compile-time calculation
    // For some reason stdlib strlen() is not constexpr
    inline constexpr int StrLen(const char * str)
    {
        int len = 0;
        while(*str++)
            len++;
        
        return len;
    }

    // constexpr integer version of pow()
    // a is base, b is exponent
    inline constexpr int Pow(int a, int b) // I wanted to do recursive, but I don't like recursive tbh, it's fugly
    {                               // This was made for Atoi(), but I actually don't need it. TODO: Remove? lol.
        int res = 1;
        for(int i = 0; i < b; i++)
            res *= a;

        return res;
    }
    
    inline constexpr bool IsUpper(char c)
    {
        return c >= 0x41 && c <= 0x5A;
    }

    inline constexpr bool IsLower(char c)
    {
        return c >= 0x61 && c <= 0x7A;
    }

    inline constexpr bool IsAlpha(char c)
    {
        return IsUpper(c) || IsLower(c);
    }

    inline constexpr bool IsDigit(char c)
    {
        return c >= 0x30 && c <= 0x39;
    }

    // If char is between A and F
    inline constexpr bool IsAF(char c)
    {
        return (c >= 0x41 && c <= 0x46);
    }

    // If char is between a and f
    inline constexpr bool Isaf(char c)
    {
        return (c >= 0x61 && c <= 0x66);
    }

    inline constexpr bool IsHex(char c)
    {
        return IsDigit(c) || IsAF(c) || Isaf(c);
    }

    // [0-9a-fA-F] to Hex value
    inline constexpr uint8_t CharToHex(char c)
    {
        if(IsDigit(c))
            return c - 0x30;

        if(IsAF(c))
            return c - 0x41 + 10;
        
        if(Isaf(c))
            return c - 0x61 + 10;

        return 0;
    }

    // Max 2 bytes (ABCD)
    inline constexpr uint16_t CharsToHex(const char* str) // TODO: Optimize. Currently not good. 
    {                                                     // remove buff and straight add to uint16_t hex
        if(!str)
            return 0;

        uint16_t hex = 0;
        std::array<char, 4> buff = {};

        int numChars = 0;

        if(*str == '0' && (str[1] == 'x' || str[1] == 'X'))
            str += 2;

        for(; *str && IsHex(*str) && numChars < 4; str++, numChars++)
            buff[numChars] = *str;
        
        if(!numChars)
            return 0;

        if(numChars == 3 && (numChars + 1) % 2 != 0 )
        {
            for(int i = numChars; i >= 0; i--)
                buff[i+1] = buff[i];
            buff[0] = '0';
            numChars++;
        }

        for(int i = 0; i < numChars; i++)
        {
            hex |= CharToHex(buff[i]) << (12 - (i*4));
        }

        return hex;
    }

    // Constexpr version of atoi() I guess
    inline constexpr int Atoi(const char* str)
    {
        if(!str || !*str)
            return 0;
        
        bool negative = false;
        int num = 0;

        switch(*str)
        {
            case '-':
                negative = true;
                // No break on purpose, that's why there is a switch here instead of if
            case '+':
                str++;
            break; // I guess no need to break, but whateva
        }


        for(; *str; str++)
        {
            if(*str < '0' || *str > '9')
                return 0; // Perhaps `return num;` so we could return the number that was translated so far
                          // Could save substringing for calls
            num *= 10;
            num += ((*str) - 0x30);
        }

        if (negative)
            num *= -1;

        return num;
    }

    inline constexpr bool IsLittleEndian()
    { 
    #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__
        #error PDP Byte order is unsupported
    #elif !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__)
        return 'ABCD' == 0x41424344UL;
    #else
        return __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__;
    #endif
        
    } 
    // This htons function is probably necessary as it's not guranteed that
    // The Regular unix/windows htons will be constexpr
    inline constexpr uint16_t Htons(uint16_t port)
    {
        if constexpr (IsLittleEndian())
        {
            return port << 8 | port >> 8;
        }
        
        return port; // Just return back the port if Big Endian, The function should not even be called on O3
    }
}

    constexpr tldnet::Host::Host(const char* hostname)
    {
        for(std::size_t i = 0; *hostname; hostname++, i++)
            m_Hostname[i] = *hostname;
    }

    constexpr tldnet::MACAddr::MACAddr(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f)
    {
        m_Address[0] = static_cast<uint64_t>(a) << 40 |
                       static_cast<uint64_t>(b) << 32 |
                       static_cast<uint64_t>(c) << 24 |
                       static_cast<uint64_t>(d) << 16 |
                       static_cast<uint64_t>(e) << 8  | f;

        SetValid(true);
    }

    // First try doing the constructor. Leaving it here for myself as history I guess if encountring future issues.
    // This function is not able to be precompile evaluated by GCC or CLANG, so written new one below
    // constexpr tldnet::IPAddress::IPAddress(const char* ipStr)
    // {
    //     // This function is C code, since I want to keep it constexprable
    //     uint8_t a = 0, b = 0, c = 0, d = 0;
    //     int numDots = 0, lastIndex = 0;
    //     char num[4] = {0};
        
    //     if(!ipStr || !*ipStr)
    //         return;
        
    //     if(ipStr[0] < '0' || ipStr[0] > '9')
    //         return;

    //     int ipStrLen = StrLen(ipStr);

    //     if(ipStrLen > 15 || ipStrLen < 7)
    //         return;
        
        

    //     for(int i = 0; i < ipStrLen; i++)
    //     {
    //         if(ipStr[i] >= '0' && ipStr[i] <= '9')
    //         {
    //             if(i - lastIndex > 2)
    //                 return;

    //             num[i-lastIndex] = ipStr[i];
    //             if(i == ipStrLen - 1)
    //                 d = Atoi(num);
    //         }
    //         else if(ipStr[i] == '.')
    //         {
    //             if(i - lastIndex == 0)
    //                 return;
                
    //             switch(numDots)
    //             {
    //                 case 0:
    //                     a = Atoi(num);
    //                 break;
    //                 case 1:
    //                     b = Atoi(num);
    //                 break;
    //                 case 2:
    //                     c = Atoi(num);
    //                 break;
    //             }
                

    //             lastIndex = i + 1;
    //             numDots++;
    //             num[0] = 0, num[1] = 0, num[2] = 0, num[3] = 0;
    //         }
    //         else
    //             return;
    //     }

    //     // *this = IPAddress(a,b,c,d); // I think we cannot do it for constexpr
    //     m_Address = a & 0xff;
    //     m_Address |= (b << 8) & 0xffff;
    //     m_Address |= (c << 16) & 0xffffff;
    //     m_Address |= (d << 24) & 0xffffffff;
        
    //     m_Valid = true;
    // }

    constexpr tldnet::IPAddress<tldnet::IPVer::IPV4>::IPAddress(const char* ipStr)
    {
        // This function is C code and not C++, since I want to keep it constexprable
        // The reason is in my opinion, parsing a literal IP address string should not cost performance
        int numDots = 0; 
        int lastIndex = 0; // Last index for dot
        
        if(!ipStr || !*ipStr)
            return;
        
        if(ipStr[0] < '0' || ipStr[0] > '9')
            return;

        int ipStrLen = StrLen(ipStr);

        if(ipStrLen > 15 || ipStrLen < 7)
            return;

        uint8_t numByte = 0;

        for(int i = 0; i < ipStrLen; i++)
        {
            if(ipStr[i] >= '0' && ipStr[i] <= '9' && i - lastIndex < 4)
            {
                numByte = numByte * 10 + (ipStr[i] - 0x30);
            }
            else if(ipStr[i] == '.')
            {
                if(numDots > 2)
                    return;

                lastIndex = i;
                m_Address[0] |= (static_cast<uint32_t>(numByte) << ((8*numDots)));
                numByte = 0;
                numDots++;
            }
            else
                return;
        }

        if(numDots != 3)
            return;

        m_Address[0] |= (static_cast<uint32_t>(numByte) << 24);
        
        SetValid(true);
    }

    constexpr tldnet::IPAddress<tldnet::IPVer::IPV4>::IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
    {
        m_Address[0] = static_cast<uint32_t>(d << 24) |
                       static_cast<uint32_t>(c << 16) |
                       static_cast<uint32_t>(b << 8) | a;

        SetValid(true);
    }

    tldnet::IPAddress<tldnet::IPVer::IPV4>::IPAddress(Host host)
    {
        if(host.GetHostname()[0] == 0)
            return;

        addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = 0; // Check if should change.

        if(getaddrinfo(host.GetHostname().data(), nullptr, &hints, &res) != 0 || !res || !res->ai_addr)
            return; // Assuming m_Valid = false;
        
        m_Address[0] = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr.s_addr; // Should not be

        freeaddrinfo(res);
    }

    constexpr tldnet::IPAddress<tldnet::IPVer::IPV6>::IPAddress(uint16_t a, uint16_t b, uint16_t c, uint16_t d, uint16_t e, uint16_t f, uint16_t g, uint16_t h)
    {
        if constexpr(IsLittleEndian())
        {
            m_Address[0] = (static_cast<uint64_t>(Htons(d)) << 48) | (static_cast<uint64_t>(Htons(c)) << 32) | (static_cast<uint64_t>(Htons(b)) << 16) | Htons(a);
            m_Address[1] = (static_cast<uint64_t>(Htons(h)) << 48) | (static_cast<uint64_t>(Htons(g)) << 32) | (static_cast<uint64_t>(Htons(f)) << 16) | Htons(e);
        }
        else
        {
            m_Address[0] = (static_cast<uint64_t>(a) << 48) | (static_cast<uint64_t>(b) << 32) | (static_cast<uint64_t>(c) << 16) | d;
            m_Address[1] = (static_cast<uint64_t>(e) << 48) | (static_cast<uint64_t>(f) << 32) | (static_cast<uint64_t>(g) << 16) | h;
        }

        SetValid(true);
    }

    tldnet::IPAddress<tldnet::IPVer::IPV6>::IPAddress(Host host)
    {
        if(host.GetHostname()[0] == 0)
            return;

        addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET6;
        hints.ai_socktype = 0; // Check if should change.

        if(getaddrinfo(host.GetHostname().data(), nullptr, &hints, &res) != 0 || !res || !res->ai_addr)
            return; // Assuming m_Valid = false;
#if PLATFORM_WINDOWS
        auto* addrArray = reinterpret_cast<sockaddr_in6*>(res->ai_addr)->sin6_addr.u.Word;
#else
        auto* addrArray = reinterpret_cast<sockaddr_in6*>(res->ai_addr)->sin6_addr.__in6_u.__u6_addr16;
#endif
        m_Address[0] = (static_cast<uint64_t>(addrArray[0]) << 48) | (static_cast<uint64_t>(addrArray[1]) << 32) | (static_cast<uint64_t>(addrArray[2]) << 16) | addrArray[3];
        m_Address[1] = (static_cast<uint64_t>(addrArray[4]) << 48) | (static_cast<uint64_t>(addrArray[5]) << 32) | (static_cast<uint64_t>(addrArray[6]) << 16) | addrArray[7];

        freeaddrinfo(res);
    }


template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL>
bool tldnet::SocketBase<IPVER, PROTOCOL>::Init()
{
    // constexpr auto IPFAM = IPVER == IPVer::IPV4 ? AF_INET : AF_INET6;
    // No need for this^, since now IPV4 == AF_INET and IPV6 == AF_INET6.

#if PLATFORM_WINDOWS
    static bool WinSock_Init = false;

    if (!WinSock_Init)
    {
        static WSADATA wsaData = {};
        if (WSAStartup(MAKEWORD(2, 2), &wsaData))
            return false;

        WinSock_Init = true;
    }
#endif
    
    if constexpr(PROTOCOL == Protocols::TCP)
    {
        this->m_Socket = socket(static_cast<int>(IPVER), SOCK_STREAM, IPPROTO_TCP);
    }
    else if constexpr(PROTOCOL == Protocols::UDP)
    {
        this->m_Socket = socket(static_cast<int>(IPVER), SOCK_DGRAM, IPPROTO_UDP);
    }
    else if constexpr(PROTOCOL == Protocols::ICMP)
    {
        this->m_Socket = socket(static_cast<int>(IPVER), SOCK_RAW, IPVER == IPVer::IPV4 ? static_cast<int>(IPPROTO_ICMP) : static_cast<int>(IPPROTO_ICMPV6)); // Casting to fix warning. GCC mind blown by comparing two unnamed enums
    }
    else
    {
        this->m_Socket = socket(static_cast<int>(IPVER), SOCK_RAW, 0);
    }

    if(this->m_Socket <= 0)
        return false;
    
    if(this->IsTimeoutSet())
    {
        for(int mode : {SO_RCVTIMEO, SO_SNDTIMEO}) // Set timeout for send and recieve (includes connection)
        {
            timeval to = {};

            if(this->m_Timeout)
            {
                to.tv_sec = this->m_Timeout / 1000;
                to.tv_usec = this->m_Timeout % 1000 * 1000;
            }
#if PLATFORM_WINDOWS
            if (setsockopt(this->m_Socket, SOL_SOCKET, mode, reinterpret_cast<const char*>(&to), sizeof(to)) < 0)
#else
            if(setsockopt(this->m_Socket, SOL_SOCKET, mode ,&to, sizeof(to)) < 0)
#endif
                return false;
        }
    }

    if(this->IsTTLSet())
    {
#if PLATFORM_WINDOWS
        if (setsockopt(this->m_Socket, IPPROTO_IP, IP_TTL, reinterpret_cast<const char*>(&this->m_TTL), sizeof(this->m_TTL)) < 0)
#else
        if(setsockopt(this->m_Socket, IPPROTO_IP, IP_TTL, &this->m_TTL, sizeof(this->m_TTL)) < 0)
#endif
            return false;
    }

    if(this->IsBroadcastEnabled())
    {
        constexpr int boolTrue = true;
#if PLATFORM_WINDOWS
        if (setsockopt(this->m_Socket, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&boolTrue), sizeof(boolTrue)) < 0)
#else
        if(setsockopt(this->m_Socket, SOL_SOCKET, SO_BROADCAST, &boolTrue, sizeof(boolTrue)) < 0)
#endif
            return false;
    }
    
    return true;
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL>
tldnet::OpResult tldnet::SocketBase<IPVER, PROTOCOL>::Send(const uint8_t* buffer, std::size_t nBytes)
{
    if(!m_Socket || !buffer || !nBytes)
        return OpResult::FAILED;

    auto res = send(m_Socket, reinterpret_cast<char*>(buffer), nBytes, 0);
    if(res > 0)
        return OpResult::OK;
    else if(res == 0)
        return OpResult::END;
    
    return OpResult::FAILED;
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL>
tldnet::OpResult tldnet::SocketBase<IPVER, PROTOCOL>::Read(uint8_t* buffer, std::size_t nBytes)
{
    if(!m_Socket || !buffer || !nBytes)
        return OpResult::FAILED;

    auto res = recv(m_Socket, reinterpret_cast<char*>(buffer), nBytes, 0);

    if(res > 0)
        return OpResult::OK;
    else if(res == 0)
        return OpResult::END;
    
    return OpResult::FAILED;
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL>
template<typename BUFFTYPE, std::size_t BUFFSIZE>
tldnet::SocketBase<IPVER, PROTOCOL>& tldnet::SocketBase<IPVER, PROTOCOL>::operator<<(std::array<BUFFTYPE, BUFFSIZE>& arr)
{
    if(!this->m_Socket)
        throw exceptions::SocketException<exceptions::SocketError::NULL_SOCKET>();

    if(!arr.size())
        throw exceptions::StringEmpty();

    std::cout << typeid(BUFFTYPE).name() << ':' << BUFFSIZE << '\n';
    if(send(m_Socket, arr.data(), sizeof(BUFFTYPE) * arr.size(), 0) < 0)
        throw exceptions::SocketException<exceptions::SocketError::FAILED_SEND>();

    return *this;
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL>
tldnet::SocketBase<IPVER, PROTOCOL>& tldnet::SocketBase<IPVER, PROTOCOL>::operator<<(const std::string& str)
{
    if(!m_Socket)
        throw exceptions::SocketException<exceptions::SocketError::NULL_SOCKET>();

    if(!str.size())
        throw exceptions::StringEmpty();

    if(send(m_Socket, str.c_str(), str.size(), 0) < 0)
        throw exceptions::SocketException<exceptions::SocketError::FAILED_SEND>();

    return *this;
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL>
tldnet::SocketBase<IPVER, PROTOCOL>& tldnet::SocketBase<IPVER, PROTOCOL>::operator<<(const char* str)
{
    if(!m_Socket)
        throw exceptions::SocketException<exceptions::SocketError::NULL_SOCKET>();

    if(!str || !*str)
        throw exceptions::StringEmpty();

    if(send(m_Socket, str, strlen(str), 0) < 0)
        throw exceptions::SocketException<exceptions::SocketError::FAILED_SEND>();
    
    return *this;
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL>
template<typename BUFFTYPE, std::size_t BUFFSIZE>
tldnet::SocketBase<IPVER, PROTOCOL>& tldnet::SocketBase<IPVER, PROTOCOL>::operator>>(std::array<BUFFTYPE, BUFFSIZE>& arr)
{
    if(!this->m_Socket)
        throw exceptions::SocketException<exceptions::SocketError::NULL_SOCKET>();
    
    if(!this->Read(arr.data(), arr.size()))
        throw exceptions::SocketException<exceptions::SocketError::FAILED_READ>();

    return *this;
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL>
tldnet::SocketBase<IPVER, PROTOCOL>& tldnet::SocketBase<IPVER, PROTOCOL>::operator>>(std::string& str)
{
    if(!m_Socket)
        throw exceptions::SocketException<exceptions::SocketError::NULL_SOCKET>();

    std::array<char, 128> buffer = {};
    
    while(this->Read(reinterpret_cast<uint8_t*>(buffer.data()), 128))
    {
        str.append(buffer.data());
        buffer = {};
    }
    
    return *this;
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL>
tldnet::SocketBase<IPVER, PROTOCOL>::~SocketBase()
{
    if(m_Socket)
    {
#if PLATFORM_WINDOWS
        shutdown(m_Socket, SD_BOTH);
        closesocket(m_Socket);
#else
        shutdown(m_Socket, SHUT_RDWR);
        close(m_Socket);
#endif
        m_Socket = 0;
    }
}

template<tldnet::IPVer IPVER,tldnet::Protocols PROTOCOL, std::size_t BUFF_SIZE>
bool tldnet::SocketClient<IPVER, PROTOCOL, BUFF_SIZE>::Create()
{
    return this->Init();
}

template<tldnet::IPVer IPVER,tldnet::Protocols PROTOCOL, std::size_t BUFF_SIZE>
bool tldnet::SocketClient<IPVER, PROTOCOL, BUFF_SIZE>::Connect()
{
    if constexpr(PROTOCOL != Protocols::TCP)
        return true;

    if(!this->m_Socket)
        return false;

    if constexpr(IPVER == IPVer::IPV6)
    {
        for(int i = 0; i < 8; i++ )
        {
            auto uint16Array = this->m_SockAddrIn.sin6_addr.__in6_u.__u6_addr16;
            uint16Array[i] = i < 4 ? reinterpret_cast<uint16_t*>(&m_Addr.GetAddressPrimitive().Get(0))[i] : reinterpret_cast<uint16_t*>(&m_Addr.GetAddressPrimitive().Get(1))[i-4];
        }
#if PLATFORM_WINDOWS
        this->m_SockAddrIn.sin6_family = static_cast<ADDRESS_FAMILY>(IPVER);
#else
        this->m_SockAddrIn.sin6_family = static_cast<sa_family_t>(IPVER);
#endif
        this->m_SockAddrIn.sin6_port = Htons(this->m_Port);
    }
    else
    {
        this->m_SockAddrIn.sin_addr.s_addr = m_Addr.GetAddressPrimitive()[0];
#if PLATFORM_WINDOWS
        this->m_SockAddrIn.sin_family = static_cast<ADDRESS_FAMILY>(IPVER);
#else
        this->m_SockAddrIn.sin_family = static_cast<sa_family_t>(IPVER);
#endif
        this->m_SockAddrIn.sin_port = Htons(this->m_Port);
    }

    return !connect(this->m_Socket, reinterpret_cast<sockaddr*>(&this->m_SockAddrIn), sizeof(this->m_SockAddrIn));
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL, tldnet::ListenScope LISTEN_SCOPE, std::size_t BUFF_SIZE>
bool tldnet::SocketServer<IPVER, PROTOCOL, LISTEN_SCOPE, BUFF_SIZE>::Create()
{
    return this->Init();
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL, tldnet::ListenScope LISTEN_SCOPE, std::size_t BUFF_SIZE>
bool tldnet::SocketServer<IPVER, PROTOCOL, LISTEN_SCOPE, BUFF_SIZE>::Bind()
{
    if(!this->m_Socket)
    {
        return false;
    }

    if constexpr(PROTOCOL == Protocols::TCP || PROTOCOL == Protocols::UDP)
    {
        const int reuseport = 1;
        if (setsockopt(this->m_Socket, SOL_SOCKET, SO_REUSEADDR, &reuseport, sizeof(reuseport)) < 0)
        {
            return false;
        }
    }

    constexpr auto listenAddress = LISTEN_SCOPE == ListenScope::LOOPBACK ? INADDR_LOOPBACK : INADDR_ANY;

    this->m_SockAddrIn.sin_addr.s_addr = htonl(listenAddress);
#if PLATFORM_WINDOWS
    this->m_SockAddrIn.sin_family = static_cast<ADDRESS_FAMILY>(IPVER);
#else
    this->m_SockAddrIn.sin_family = static_cast<sa_family_t>(IPVER);
#endif
    this->m_SockAddrIn.sin_port = Htons(this->m_Port);
    //int res = 0; Use when error checking implemented

    if(bind(this->m_Socket, reinterpret_cast<sockaddr*>(&this->m_SockAddrIn), sizeof(this->m_SockAddrIn)) < 0)
    {
        return false;
    }

    if(listen(this->m_Socket, SOMAXCONN) < 0)
    {
        return false;
    }

    return true;
}

template<tldnet::IPVer IPVER, tldnet::Protocols PROTOCOL, tldnet::ListenScope LISTEN_SCOPE, std::size_t BUFF_SIZE>
tldnet::Socket<IPVER, PROTOCOL> tldnet::SocketServer<IPVER, PROTOCOL, LISTEN_SCOPE, BUFF_SIZE>::Listen()
{
    Socket<IPVER, PROTOCOL> newSocket;
    constexpr socklen_t addrInSize = sizeof(this->m_SockAddrIn);
    int sockfd = accept(this->m_Socket, reinterpret_cast<sockaddr*>(&this->m_SockAddrIn), const_cast<socklen_t*>(&addrInSize));

    if(sockfd > 0)
        newSocket.SetSocketFD(sockfd);

    return newSocket;
}

#endif