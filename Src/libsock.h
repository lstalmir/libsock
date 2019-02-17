#ifndef __libsock_h_
#define __libsock_h_
#ifndef RC_INVOKED
#include <memory>
#include <istream>
#include <ostream>
#include <iostream>
#include <system_error>

#if defined( _WIN32 ) || defined( _WIN64 ) || defined( WIN32 )

#if __has_include(<sdkddkver.h>)
#include <sdkddkver.h>
#endif

#ifdef _WIN32_WINNT
#define OS_WINDOWS

#include <WinSock2.h>

#if __has_include(<WS2tcpip.h>)
#define WINDOWS_IP
#include <WS2tcpip.h>
#endif

#if __has_include(<WSNwLink.h>)
#define WINDOWS_IPX
#include <WSNwLink.h>
#endif

#if __has_include(<AF_Irda.h>)
#define WINDOWS_IRDA
#include <AF_Irda.h>
#endif

#if __has_include(<atalkwsh.h>)
#define WINDOWS_APPLETALK
#include <atalkwsh.h>
#endif

#if defined( _WIN32_WINNT_NT4 ) && ( _WIN32_WINNT >=_WIN32_WINNT_NT4 )
#define WINNT_4_0
#define OS_WINDOWS_NT

#if defined( _WIN32_WINNT_WIN2K ) && ( _WIN32_WINNT >= _WIN32_WINNT_WIN2K )
#define WINNT_5_0
#define OS_WINDOWS_2000

#if defined( _WIN32_WINNT_WINXP ) && ( _WIN32_WINNT >= _WIN32_WINNT_WINXP )
#define WINNT_5_1
#define OS_WINDOWS_XP
#define OS_WINDOWS_SERVER_2003

#if defined( _WIN32_WINNT_WS03 ) && ( _WIN32_WINNT >= _WIN32_WINNT_WS03 )
#define WINNT_5_2
#define OS_WINDOWS_XP_SP2
#define OS_WINDOWS_SERVER_2003_SP1

#if defined( _WIN32_WINNT_VISTA ) && ( _WIN32_WINNT >= _WIN32_WINNT_VISTA )
#define WINNT_6_0
#define OS_WINDOWS_VISTA
#define OS_WINDOWS_SERVER_2008

#if defined( _WIN32_WINNT_WIN7 ) && ( _WIN32_WINNT >= _WIN32_WINNT_WIN7 )
#define WINNT_6_1
#define OS_WINDOWS_7
#define OS_WINDOWS_SERVER_2008_R2

#if defined( _WIN32_WINNT_WIN8 ) && ( _WIN32_WINNT >= _WIN32_WINNT_WIN8 )
#define WINNT_6_2
#define OS_WINDOWS_8
#define OS_WINDOWS_SERVER_2012

#if defined( _WIN32_WINNT_WINBLUE ) && ( _WIN32_WINNT >= _WIN32_WINNT_WINBLUE )
#define WINNT_6_3
#define OS_WINDOWS_8_1
#define OS_WINDOWS_SERVER_2012_R2

#if defined( _WIN32_WINNT_WIN10 ) && ( _WIN32_WINNT >= _WIN32_WINNT_WIN10 )
#define WINNT_10_0
#define OS_WINDOWS_10
#define OS_WINDOWS_SERVER_2016

//          WINNT_10_0, WINDOWS 10
#endif  //  WINNT_6_3, WINDOWS 8.1
#endif  //  WINNT_6_2, WINDOWS 8
#endif  //  WINNT_6_1, WINDOWS 7
#endif  //  WINNT_6_0, WINDOWS VISTA
#endif  //  WINNT_5_2, WINDOWS XP SP2
#endif  //  WINNT_5_1, WINDOWS XP
#endif  //  WINNT_5_0, WINDOWS 2000
#endif  //  WINNT_4_0, WINDOWS NT
#endif  //  WINDOWS
#endif

#elif defined( __POSIX__ )
#define OS_LINUX

#include <sys/socket.h>

#else
#error Unknown target OS

#endif

#define _LIBSOCK ::libsock::

#define _LIBSOCK_CHECK_ARG_NOT_NULL( ARG ) \
    if( (ARG) == nullptr ) \
        throw std::invalid_argument( #ARG " cannot be NULL" );

#define _LIBSOCK_CHECK_ARG_NOT_EQ( ARG, VAL ) \
    if( (ARG) == (VAL) ) \
        throw std::invalid_argument( #ARG " cannot be " #VAL ); 


namespace libsock
{

namespace __impl
{
#if defined( OS_WINDOWS ) \
 || defined( OS_LINUX )
using ::socket;
using ::closesocket;
using ::shutdown;
using ::connect;
using ::accept;
using ::bind;
using ::listen;
using ::setsockopt;
using ::getsockopt;
using ::send;
using ::sendto;
using ::recv;
using ::recvfrom;

#else
#error Socket functions not defined for this OS
#endif

inline int geterror( int _Retval ) noexcept
    {   // gets last error reported by the sockets API
#if defined( OS_WINDOWS )
    (_Retval); // Unreferenced in this OS
    return WSAGetLastError();
#else
    return _Retval;
#endif
    }
}

#if defined( OS_WINDOWS )
typedef SOCKET _Socket_handle;
constexpr _Socket_handle _Invalid_socket = INVALID_SOCKET;

#elif defined( OS_LINUX )
typedef int _Socket_handle;
constexpr _Socket_handle _Invalid_socket = -1;

#else
#error _Socket_handle not defined for this OS
#endif


// CLASS _Socket_error_category
class _Socket_error_category
    : public std::error_category
    {
public:
    _NODISCARD inline virtual const char* name() const noexcept override
        {
        return "libsock error";
        }

    _NODISCARD inline virtual std::string message( int _Errval ) const override
        {
        std::string msg = "Unable to retrieve error message";

#   if defined( OS_WINDOWS )
        // Windows OSes provide FormatMessage function, which translates error messages
        // into human-readable forms.
        char* msg_buffer = nullptr;

        ::FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            _Errval,
            MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
            (char*)(&msg_buffer), 0,
            nullptr );

        if( msg_buffer != nullptr )
            { // Copy obtained message to the output string and free the memory.
            msg.assign( msg_buffer );
            ::LocalFree( msg_buffer );
            }

#   elif defined( OS_LINUX )

#   else
#   error _Socket_error_category::message: Messages not implemented for this OS
#   endif
        return msg;
        }
    };


// CLASS socket_exception
class socket_exception
    : public std::system_error
    {
typedef std::system_error _Base;

public:
    inline socket_exception( int _Errval )
        : _Base( _Errval, _Socket_error_category{} )
        {   // construct basic socket exception
        }
    };


// CLASS libsock_scope
class libsock_scope
    {
public:
    inline libsock_scope()
        {   // initialize socket library
#   if defined( OS_WINDOWS )
        WSADATA wsaData;
        if( WSAStartup( MAKEWORD( 2, 0 ), &wsaData ) != ERROR_SUCCESS )
            throw socket_exception( ::WSAGetLastError() );
        (wsaData); // avoid 'not referenced' warnings
#   endif
        }

    inline ~libsock_scope() noexcept
        {   // deinitialize socket library
#   if defined( OS_WINDOWS )
        ::WSACleanup();
#   endif
        }
    };


enum class address_family
    {
    unknown             = -1,               // Unknown
    unspec              = AF_UNSPEC,        // Unspecified
    local               = AF_UNIX,          // Local to host (pipes, portals)
    inet                = AF_INET,          // Internet IP protocol version 4 (IPv4)
#if defined( OS_WINDOWS )
    x25                 = AF_CCITT,         // Reserved for X.25 project
    ax25                = AF_CCITT,         // Amateur Radio AX.25
    rose                = AF_CCITT,         // Amateur Radio X.25 PLP
#elif defined( OS_LINUX )
    x25                 = AF_X25,           // Reserved for X.25 project
    ax25                = AF_AX25,          // Amateur Radio AX.25
    rose                = AF_ROSE,          // Amateur Radio X.25 PLP
#endif
#if defined( OS_WINDOWS )
    implink             = AF_IMPLINK,       // ARPANET IMP address
    pup                 = AF_PUP,           // PUP protocols
    chaos               = AF_CHAOS,         // MIT CHAOS protocols
    ns                  = AF_NS,            // XEROX NS protocols
    ipx                 = AF_IPX,           // Novell IPX protocols
    iso                 = AF_ISO,           // ISO protocols
    osi                 = AF_OSI,           // OSI protocols
    ecma                = AF_ECMA,          // European Computer Manufacturers
    datakit             = AF_DATAKIT,       // DATAKIT protocols
    sna                 = AF_SNA,           // IBM SNA
    decnet              = AF_DECnet,        // DECnet
    dli                 = AF_DLI,           // Direct data link interface
    lat                 = AF_LAT,           // LAT
    hylink              = AF_HYLINK,        // NSC Hyperchannel
    appletalk           = AF_APPLETALK,     // AppleTalk
    netbios             = AF_NETBIOS,       // NetBIOS-style address
    voiceview           = AF_VOICEVIEW,     // VoiceView
    firefox             = AF_FIREFOX,       // FireFox protocols
    banyan              = AF_BAN,           // Banyan
    atm                 = AF_ATM,           // Native ATM services
    inet6               = AF_INET6,         // Internet IP protocol version 6 (IPv6)
    cluster             = AF_CLUSTER,       // Microsoft Wolfpack
    ieee1284_4          = AF_12844,         // IEEE 1284.4 WG AF
    irda                = AF_IRDA,          // IrDA
    netdes              = AF_NETDES,        // Network Designers OSI & gateway
#ifdef OS_WINDOWS_XP
    tcnprocess          = AF_TCNPROCESS,    // 
    tcnmessage          = AF_TCNMESSAGE,    //
    iclfxbm             = AF_ICLFXBM,       //
#ifdef OS_WINDOWS_VISTA
    bluetooth           = AF_BTH,           // Bluetooth RFCOMM/L2CAP protocols
#ifdef OS_WINDOWS_7
    link                = AF_LINK,          //
#ifdef OS_WINDOWS_10
    hyperv              = AF_HYPERV,        //
#endif // OS_WINDOWS_10
#endif // OS_WINDOWS_7
#endif // OS_WINDOWS_VISTA
#endif // OS_WINDOWS_XP
#elif defined( OS_LINUX )
    atmpvc              ,                   // ATM PVCs
    ieee802154          ,                   // IEEE 802154 sockets
    infiniband          = AF_IB,            // Native InfiniBand address
    isdn                = AF_ISDN,          // mISDN sockets
    xdp                 = AF_XDP,           // XDP sockets
    nfc                 = AF_NFC,           // NFC sockets
    bluetooth           = AF_BLUETOOTH,     // Bluetooth RFCOMM/L2CAP protocols
    bridge,             = AF_BRIDGE         // Multiprotocol bridge
    netlink,                                // 
    netrom,                                 // Amateur Radio NET/ROM
    netbeui,                                // Reserved for 802.2LLC project
    security,                               // Security callback pseudo address family
    key,                                    // Key management API
    packet,                                 // Packet family
    ash,                                    // Ash
    econet,                                 // Acorn Econet
    rds,                                    // RDS sockets
    pppox,                                  // PPPoX sockets
    wanpipe,                                // Wanpipe API Sockets
    llc,                                    // Linux LLC
    mpls,                                   // MPLS
    can,                                    // Controller Area Network
    tipc,                                   // TIPC sockets
    iucv,                                   // IUCV sockets
    rxrpc,                                  // RxRPC sockets
    phonet,                                 // Phonet sockets
    caif,                                   // CAIF sockets
    algorithm,                              // Algorithm sockets
    vsock,                                  // vSockets
    kcm,                                    // Kernel Connection Multiplexor
    qipcrtr,                                // Qualcomm IPC Router
    smc                                     //
#endif
    };


// ENUM CLASS socket_type
enum class socket_type
    {
    unknown             = -1,               //
    stream              = SOCK_STREAM,      // Reliable stream socket
    datagram            = SOCK_DGRAM,       // Unreliable datagram socket
    rdm                 = SOCK_RDM,         // Reliable datagram socket
    seqpacket           = SOCK_SEQPACKET,   // Pseudo-stream datagram socket
    raw                 = SOCK_RAW          // Raw socket
    };


enum class protocol
    {
    unknown             = -1,               //
    unspec              = 0,                // Unspecified
#if defined( OS_WINDOWS )
    ip_hopopts          = IPPROTO_HOPOPTS,  // 
    ip_icmp             = IPPROTO_ICMP,     // ICMP protocol
    ip_igmp             = IPPROTO_IGMP,     // IGMP protocol
    ip_ggp              = IPPROTO_GGP,      //
    ip_ipv4             = IPPROTO_IPV4,     //
    ip_st               = IPPROTO_ST,       //
    ip_tcp              = IPPROTO_TCP,      // TCP/IP protocol
    ip_cbt              = IPPROTO_CBT,      //
    ip_egp              = IPPROTO_EGP,      //
    ip_igp              = IPPROTO_IGP,      //
    ip_pup              = IPPROTO_PUP,      //
    ip_udp              = IPPROTO_UDP,      // UDP/IP protocol
    ip_idp              = IPPROTO_IDP,      //
    ip_rdp              = IPPROTO_RDP,      // RDP (remote desktop) protocol
    ip_ipv6             = IPPROTO_IPV6,     //
    ip_routing          = IPPROTO_ROUTING,  //
    ip_fragment         = IPPROTO_FRAGMENT, //
    ip_esp              = IPPROTO_ESP,      //
    ip_ah               = IPPROTO_AH,       //
    ip_icmpv6           = IPPROTO_ICMPV6,   //
    ip_none             = IPPROTO_NONE,     //
    ip_dstopts          = IPPROTO_DSTOPTS,  //
    ip_nd               = IPPROTO_ND,       //
    ip_iclfxbm          = IPPROTO_ICLFXBM,  //
    ip_pim              = IPPROTO_PIM,      //
    ip_pgm              = IPPROTO_PGM,      //
    ip_l2tp             = IPPROTO_L2TP,     //
    ip_sctp             = IPPROTO_SCTP,     //
    ip_raw              = IPPROTO_RAW       //
#elif defined( OS_LINUX )
    ip_hopopts          = IPPROTO_HOPOPTS,  // 
    ip_icmp             = IPPROTO_ICMP,     // ICMP protocol
    ip_igmp             = IPPROTO_IGMP,     // IGMP protocol
    ip_ggp              = IPPROTO_GGP,      //
    ip_ipv4             = IPPROTO_IPV4,     //
    ip_st               = IPPROTO_ST,       //
    ip_tcp              = IPPROTO_TCP,      // TCP/IP protocol
    ip_cbt              = IPPROTO_CBT,      //
    ip_egp              = IPPROTO_EGP,      //
    ip_igp              = IPPROTO_IGP,      //
    ip_pup              = IPPROTO_PUP,      //
    ip_udp              = IPPROTO_UDP,      // UDP/IP protocol
    ip_idp              = IPPROTO_IDP,      //
    ip_rdp              = IPPROTO_RDP,      // RDP (remote desktop) protocol
    ip_ipv6             = IPPROTO_IPV6,     //
    ip_routing          = IPPROTO_ROUTING,  //
    ip_fragment         = IPPROTO_FRAGMENT, //
    ip_esp              = IPPROTO_ESP,      //
    ip_ah               = IPPROTO_AH,       //
    ip_icmpv6           = IPPROTO_ICMPV6,   //
    ip_none             = IPPROTO_NONE,     //
    ip_dstopts          = IPPROTO_DSTOPTS,  //
    ip_nd               = IPPROTO_ND,       //
    ip_iclfxbm          = IPPROTO_ICLFXBM,  //
    ip_pim              = IPPROTO_PIM,      //
    ip_pgm              = IPPROTO_PGM,      //
    ip_l2tp             = IPPROTO_L2TP,     //
    ip_sctp             = IPPROTO_SCTP,     //
    ip_raw              = IPPROTO_RAW       //
#else
#error IP protocols not defined for this OS
#endif
    };


enum class socket_opt_ip
    {
    unknown             = -1,
    join_group          = IP_ADD_MEMBERSHIP,
    leave_group         = IP_DROP_MEMBERSHIP,
    join_source_group   = IP_ADD_SOURCE_MEMBERSHIP,
    leave_source_group  = IP_DROP_SOURCE_MEMBERSHIP,
    block_source        = IP_BLOCK_SOURCE,
    unblock_source      = IP_UNBLOCK_SOURCE,
    dont_fragment       = IP_DONTFRAGMENT,
    header_included     = IP_HDRINCL,
    mtu,
    mtu_discover,
    multicast_interface = IP_MULTICAST_IF,
    multicast_loop      = IP_MULTICAST_LOOP,
    multicast_ttl       = IP_MULTICAST_TTL,
    original_arrival_interface = IP_ORIGINAL_ARRIVAL_IF,
    ttl                 = IP_TTL,
    type_of_service     = IP_TOS,
    unicast_interface   = IP_UNICAST_IF,
    recv_interface      = IP_RECVIF,
    recv_dest_address   = IP_RECVDSTADDR,
    recv_broadcast      = IP_RECEIVE_BROADCAST,
    interface_list_enable = IP_IFLIST,
    interface_list_add  = IP_ADD_IFLIST,
    interface_list_delete = IP_DEL_IFLIST,
    routing_header      = IP_RTHDR,
    recv_routing_header = IP_RECVRTHDR,
    packet_info         = IP_PKTINFO,
    hop_limit           = IP_HOPLIMIT,
    packet_traffic_class = IP_TCLASS,
    recv_packet_traffic_class = IP_RECVTCLASS,
    ecn                 = IP_ECN,
    packet_info_ext     = IP_PKTINFO_EX
    };


template<typename _SockOptT>
struct _Socket_opt_level;

template<>
struct _Socket_opt_level<socket_opt_ip>
    { static constexpr int value = IPPROTO_IP; };


// CLASS socket
class socket
    {
public:
    inline socket( address_family _Family, socket_type _Type, protocol _Protocol )
        : _MyHandle( _Invalid_socket )
        , _MyAddr_family( _Family )
        , _MyType( _Type )
        , _MyProtocol( _Protocol )
        {   // construct socket object
        this->_MyHandle = _LIBSOCK __impl::socket(
            static_cast<int>(_Family),
            static_cast<int>(_Type),
            static_cast<int>(_Protocol) );
        _Throw_if_failed( (int)(this->_MyHandle) );
        }

    inline virtual ~socket() noexcept
        {   // destroy socket object
        _Invoke_socket_func_nothrow( _LIBSOCK __impl::closesocket );
        this->_MyHandle = _Invalid_socket;
        }

    template<typename _SockOptT>
    inline void set_opt( _SockOptT _Opt, const void* _Optval, size_t _Optlen )
        {   // set socket option value
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optval );
        _LIBSOCK_CHECK_ARG_NOT_EQ( _Optlen, 0 );
        _Invoke_socket_func( _LIBSOCK __impl::setsockopt,
            _Socket_opt_level<_SockOptT>::value,
            static_cast<int>(_Opt),
            reinterpret_cast<const char*>(_Optval),
            static_cast<int>(_Optlen) );
        }

    template<typename _SockOptT>
    inline void get_opt( _SockOptT _Opt, void* _Optval, size_t* _Optlen ) const
        {   // get socket option value
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optval );
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optlen );
        _LIBSOCK_CHECK_ARG_NOT_EQ( *_Optlen, 0 );
        int optlen = (_Optlen) ? static_cast<int>(*_Optlen) : 0;
        _Invoke_socket_func( _LIBSOCK __impl::getsockopt,
            _Socket_opt_level<_SockOptT>::value,
            static_cast<int>(_Opt),
            reinterpret_cast<char*>(_Optval),
            _Optlen ? &optlen : nullptr );
        if( _Optlen != nullptr )
            (*_Optlen) = static_cast<size_t>(optlen);
        }

    inline virtual int send( const void* _Data, size_t _ByteSize, int _Flags = 0 )
        {   // send message to the remote host
        if( _ByteSize == 0 ) return 0;
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Data );
        return _Invoke_socket_func( _LIBSOCK __impl::send,
            reinterpret_cast<const char*>(_Data),
            static_cast<int>(_ByteSize),
            _Flags );
        }

    inline virtual int recv( void* _Data, size_t _ByteSize, int _Flags = 0 )
        {   // receive message from the remote host
        if( _ByteSize == 0 ) return 0;
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Data );
        return _Invoke_socket_func( _LIBSOCK __impl::recv,
            reinterpret_cast<char*>(_Data),
            static_cast<int>(_ByteSize),
            _Flags );
        }

    template<typename _SockAddrTy>
    inline void bind( _SockAddrTy* _Addr, size_t _Addrlen )
        {   // bind socket to the network interface
        _Invoke_socket_func( _LIBSOCK __impl::bind,
            reinterpret_cast<sockaddr*>(_Addr),
            static_cast<int>(_Addrlen) );
        }

    inline void listen( size_t _QueueLength = SOMAXCONN )
        {   // start listening for incoming connections
        _Invoke_socket_func( _LIBSOCK __impl::listen,
            static_cast<int>(_QueueLength) );
        }

    template<typename _SockAddrTy>
    inline void connect( _SockAddrTy* _Addr, size_t _Addrlen )
        {   // connect to the remote host
        return _Invoke_socket_func( _LIBSOCK __impl::connect,
            reinterpret_cast<sockaddr*>(_Addr),
            static_cast<int>(_Addrlen) );
        }

    _NODISCARD inline socket accept()
        {   // accept incoming connection from the client
        return accept<sockaddr>( nullptr, nullptr );
        }

    template<typename _SockAddrTy>
    _NODISCARD inline socket accept( _SockAddrTy* _Addr, size_t* _Addrlen )
        {   // accept incoming connection from the client
        int addrlen = (_Addrlen) ? static_cast<int>(*_Addrlen) : 0;
        socket accepted = _Invoke_socket_func( _LIBSOCK __impl::accept,
            reinterpret_cast<sockaddr*>(_Addr),
            (_Addrlen) ? &addrlen : nullptr );
        if( _Addrlen != nullptr )
            (*_Addrlen) = static_cast<size_t>(addrlen);
        return accepted;
        }

public:
    template<typename _Ty>
    inline socket& operator<<( const _Ty& _Data )
        {   // send message through socket stream
        if( !_Is_stream_socket() )
            { // the socket is not stream-like
            throw std::exception( "Cannot use stream operations on non-stream socket" );
            }
        if( send( &_Data, sizeof( _Ty ) ) != static_cast<int>(sizeof( _Ty )) )
            { // send failed without raising errors?
            _Throw_if_failed( -1 );
            }
        return (*this);
        }

    template<typename _Ty>
    inline socket& operator>>( _Ty& _Data )
        {   // receive message through socket stream
        if( !_Is_stream_socket() )
            { // the socket is not stream-like
            throw std::exception( "Cannot use stream operations on non-stream socket" );
            }
        if( recv( &_Data, sizeof( _Ty ) ) != static_cast<int>(sizeof( _Ty )) )
            { // recv failed without raising errors?
            _Throw_if_failed( -1 );
            }
        return (*this);
        }

public:
    _NODISCARD inline _Socket_handle get_native_handle() const noexcept
        {   // retrieve native socket handle
        return this->_MyHandle;
        }

    _NODISCARD inline address_family get_address_family() const noexcept
        {   // get socket address family
        return this->_MyAddr_family;
        }

    _NODISCARD inline socket_type get_socket_type() const noexcept
        {   // get socket type
        return this->_MyType;
        }

    _NODISCARD inline protocol get_protocol() const noexcept
        {   // get socket protocol
        return this->_MyProtocol;
        }

protected:
    _Socket_handle _MyHandle;
    address_family _MyAddr_family;
    socket_type _MyType;
    protocol _MyProtocol;

    inline socket( _Socket_handle _Handle = _Invalid_socket ) noexcept
        : _MyHandle( _Handle )
        , _MyAddr_family( address_family::unknown )
        , _MyType( socket_type::unknown )
        , _MyProtocol( protocol::unknown )
        {   // construct socket object from existing handle
        }

    inline bool _Is_stream_socket() const noexcept
        {   // checks if the socket is reliable, stream one
        return (this->_MyType == socket_type::stream)
            || (this->_MyType == socket_type::seqpacket);
        }

    template<typename _Fx, typename... _Ax>
    inline auto _Invoke_socket_func( _Fx&& _Func, _Ax... _Args ) const
        {   // invoke socket function and raise exception on error
        auto result = _Func( this->_MyHandle, _Args... );
        _Throw_if_failed( (int)(result) );
        return result;
        }

    template<typename _Fx, typename... _Ax>
    inline auto _Invoke_socket_func_nothrow( _Fx&& _Func, _Ax... _Args ) const noexcept
        {   // invoke socket function without raising exception on error
        return _Func( this->_MyHandle, _Args... );
        }

    inline void _Throw_if_failed( int _Retval ) const
        {   // throw exception if _Retval indicates error
        if( _Retval < 0 )
            { // assume that all negative return values indicate error
            throw socket_exception( _LIBSOCK __impl::geterror( _Retval ) );
            }
        }

    };

}// libsock

#endif// RC_INVOKED
#endif// __libsock_h_
