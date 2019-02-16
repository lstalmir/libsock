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

using ::socket;
using ::bind;
using ::listen;
using ::connect;
using ::accept;
using ::shutdown;
using ::closesocket;
using ::send;
using ::sendto;
using ::recv;
using ::recvfrom;
using ::setsockopt;
using ::getsockopt;


#if defined( OS_WINDOWS )
typedef SOCKET _Socket_handle;
constexpr _Socket_handle _Invalid_socket = INVALID_SOCKET;

#elif defined( OS_LINUX )
typedef int _Socket_handle;
constexpr _Socket_handle _Invalid_socket = -1;

#else
#error _Socket_handle not defined for this OS
#endif


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
            LocalFree( msg_buffer );
            }

#   elif defined( OS_LINUX )

#   else
#   error _Socket_error_category::message: Messages not implemented for this OS
#   endif
        return msg;
        }
    };


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


class libsock_scope
    {
public:
    inline libsock_scope()
        {   // initialize socket library
#   if defined( OS_WINDOWS )
        WSADATA wsaData;
        if( WSAStartup( MAKEWORD( 2, 0 ), &wsaData ) != ERROR_SUCCESS )
            throw socket_exception( WSAGetLastError() );
        (wsaData); // avoid 'not referenced' warnings
#   endif
        }

    inline ~libsock_scope() noexcept
        {   // deinitialize socket library
#   if defined( OS_WINDOWS )
        WSACleanup();
#   endif
        }
    };


enum class address_family
    {
    af_unknown          = -1,               // Unknown
    af_unspec           = AF_UNSPEC,        // Unspecified
    af_local            = AF_UNIX,          // Local to host (pipes, portals)
    af_inet             = AF_INET,          // Internet IP protocol version 4 (IPv4)
#if defined( OS_WINDOWS )
    af_x25              = AF_CCITT,         // Reserved for X.25 project
    af_ax25             = AF_CCITT,         // Amateur Radio AX.25
    af_rose             = AF_CCITT,         // Amateur Radio X.25 PLP
#elif defined( OS_LINUX )
    af_x25              = AF_X25,           // Reserved for X.25 project
    af_ax25             = AF_AX25,          // Amateur Radio AX.25
    af_rose             = AF_ROSE,          // Amateur Radio X.25 PLP
#endif
#if defined( OS_WINDOWS )
    af_implink          = AF_IMPLINK,       // ARPANET IMP address
    af_pup              = AF_PUP,           // PUP protocols
    af_chaos            = AF_CHAOS,         // MIT CHAOS protocols
    af_ns               = AF_NS,            // XEROX NS protocols
    af_ipx              = AF_IPX,           // Novell IPX protocols
    af_iso              = AF_ISO,           // ISO protocols
    af_osi              = AF_OSI,           // OSI protocols
    af_ecma             = AF_ECMA,          // European Computer Manufacturers
    af_datakit          = AF_DATAKIT,       // DATAKIT protocols
    af_sna              = AF_SNA,           // IBM SNA
    af_decnet           = AF_DECnet,        // DECnet
    af_dli              = AF_DLI,           // Direct data link interface
    af_lat              = AF_LAT,           // LAT
    af_hylink           = AF_HYLINK,        // NSC Hyperchannel
    af_appletalk        = AF_APPLETALK,     // AppleTalk
    af_netbios          = AF_NETBIOS,       // NetBIOS-style address
    af_voiceview        = AF_VOICEVIEW,     // VoiceView
    af_firefox          = AF_FIREFOX,       // FireFox protocols
    af_banyan           = AF_BAN,           // Banyan
    af_atm              = AF_ATM,           // Native ATM services
    af_inet6            = AF_INET6,         // Internet IP protocol version 6 (IPv6)
    af_cluster          = AF_CLUSTER,       // Microsoft Wolfpack
    af_ieee1284_4       = AF_12844,         // IEEE 1284.4 WG AF
    af_irda             = AF_IRDA,          // IrDA
    af_netdes           = AF_NETDES,        // Network Designers OSI & gateway
#ifdef OS_WINDOWS_XP
    af_tcnprocess       = AF_TCNPROCESS,    // 
    af_tcnmessage       = AF_TCNMESSAGE,    //
    af_iclfxbm          = AF_ICLFXBM,       //
#ifdef OS_WINDOWS_VISTA
    af_bluetooth        = AF_BTH,           // Bluetooth RFCOMM/L2CAP protocols
#ifdef OS_WINDOWS_7
    af_link             = AF_LINK,          //
#ifdef OS_WINDOWS_10
    af_hyperv           = AF_HYPERV,        //
#endif // OS_WINDOWS_10
#endif // OS_WINDOWS_7
#endif // OS_WINDOWS_VISTA
#endif // OS_WINDOWS_XP
#elif defined( OS_LINUX )
    af_atmpvc           ,                   // ATM PVCs
    af_ieee802154       ,                   // IEEE 802154 sockets
    af_infiniband       = AF_IB,            // Native InfiniBand address
    af_isdn             = AF_ISDN,          // mISDN sockets
    af_xdp              = AF_XDP,           // XDP sockets
    af_nfc              = AF_NFC,           // NFC sockets
    af_bridge,                              // Multiprotocol bridge
    af_netlink,                             // 
    af_netrom,                              // Amateur Radio NET/ROM
    af_netbeui,                             // Reserved for 802.2LLC project
    af_security,                            // Security callback pseudo address family
    af_key,                                 // Key management API
    af_packet,                              // Packet family
    af_ash,                                 // Ash
    af_econet,                              // Acorn Econet
    af_rds,                                 // RDS sockets
    af_pppox,                               // PPPoX sockets
    af_wanpipe,                             // Wanpipe API Sockets
    af_llc,                                 // Linux LLC
    af_mpls,                                // MPLS
    af_can,                                 // Controller Area Network
    af_tipc,                                // TIPC sockets
    af_iucv,                                // IUCV sockets
    af_rxrpc,                               // RxRPC sockets
    af_phonet,                              // Phonet sockets
    af_caif,                                // CAIF sockets
    af_algorithm,                           // Algorithm sockets
    af_vsock,                               // vSockets
    af_kcm,                                 // Kernel Connection Multiplexor
    af_qipcrtr,                             // Qualcomm IPC Router
    af_smc                                  //
#endif
    };


enum class socket_type
    {
    sock_unknown        = -1,               //
#if defined( OS_WINDOWS )
    sock_rdm            = SOCK_RDM,         //
#endif
    sock_stream         = SOCK_STREAM,      //
    sock_datagram       = SOCK_DGRAM,       //
    sock_raw            = SOCK_RAW,         //
    sock_seqpacket      = SOCK_SEQPACKET    //
    };


enum class protocol
    {
    ipproto_unknown     = -1,               //
    ipproto_hopopts     = IPPROTO_HOPOPTS,  //
    ipproto_icmp        = IPPROTO_ICMP,     //
    ipproto_igmp        = IPPROTO_IGMP,     //
    ipproto_ggp         = IPPROTO_GGP,      //
    ipproto_ipv4        = IPPROTO_IPV4,     //
    ipproto_st          = IPPROTO_ST,       //
    ipproto_tcp         = IPPROTO_TCP,      //
    ipproto_cbt         = IPPROTO_CBT,      //
    ipproto_egp         = IPPROTO_EGP,      //
    ipproto_igp         = IPPROTO_IGP,      //
    ipproto_pup         = IPPROTO_PUP,      //
    ipproto_udp         = IPPROTO_UDP,      //
    ipproto_idp         = IPPROTO_IDP,      //
    ipproto_rdp         = IPPROTO_RDP,      //
    ipproto_ipv6        = IPPROTO_IPV6,     //
    ipproto_routing     = IPPROTO_ROUTING,  //
    ipproto_fragment    = IPPROTO_FRAGMENT, //
    ipproto_esp         = IPPROTO_ESP,      //
    ipproto_ah          = IPPROTO_AH,       //
    ipproto_icmpv6      = IPPROTO_ICMPV6,   //
    ipproto_none        = IPPROTO_NONE,     //
    ipproto_dstopts     = IPPROTO_DSTOPTS,  //
    ipproto_nd          = IPPROTO_ND,       //
    ipproto_iclfxbm     = IPPROTO_ICLFXBM,  //
    ipproto_pim         = IPPROTO_PIM,      //
    ipproto_pgm         = IPPROTO_PGM,      //
    ipproto_l2tp        = IPPROTO_L2TP,     //
    ipproto_sctp        = IPPROTO_SCTP,     //
    ipproto_raw         = IPPROTO_RAW       //
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


class _Basic_socket
    {
public:
    inline _Basic_socket( address_family _Family, socket_type _Type, protocol _Protocol )
        : _Handle( _Invalid_socket )
        {   // construct socket object
        _Handle = _LIBSOCK socket(
            static_cast<int>(_Family),
            static_cast<int>(_Type),
            static_cast<int>(_Protocol) );
        _Throw_if_failed( (int)(_Handle) );
        _Addr_family = _Family;
        }

    inline virtual ~_Basic_socket() noexcept
        {   // destroy socket object
        _Invoke_socket_func_nothrow( _LIBSOCK closesocket );
        _Handle = _Invalid_socket;
        }

    _NODISCARD inline _Socket_handle get_native_handle() const noexcept
        {   // retrieve native socket handle
        return _Handle;
        }

    template<
        typename _SockOptT
    > [[noreturn]] inline void set_opt( _SockOptT _Opt, const void* _Optval, size_t _Optlen )
        {   // set socket option value
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optval );
        _LIBSOCK_CHECK_ARG_NOT_EQ( _Optlen, 0 );
        _Invoke_socket_func( _LIBSOCK setsockopt,
            _Socket_opt_level<_SockOptT>::value,
            static_cast<int>(_Opt),
            reinterpret_cast<const char*>(_Optval),
            static_cast<int>(_Optlen) );
        }

    template<
        typename _SockOptT
    > [[noreturn]] inline void get_opt( _SockOptT _Opt, void* _Optval, size_t* _Optlen ) const
        {   // get socket option value
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optval );
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optlen );
        _LIBSOCK_CHECK_ARG_NOT_EQ( *_Optlen, 0 );
        int optlen = (_Optlen) ? static_cast<int>(*_Optlen) : 0;
        _Invoke_socket_func( _LIBSOCK getsockopt,
            _Socket_opt_level<_SockOptT>::value,
            static_cast<int>(_Opt),
            reinterpret_cast<char*>(_Optval),
            _Optlen ? &optlen : nullptr );
        if( _Optlen != nullptr )
            (*_Optlen) = static_cast<size_t>(optlen);
        }

    template<
        typename _Ty
    > [[noreturn]] inline void bind( _Ty* _Addr, size_t _Addrlen )
        {   // bind socket to the network interface
        _Invoke_socket_func( _LIBSOCK bind,
            reinterpret_cast<sockaddr*>(_Addr),
            static_cast<int>(_Addrlen) );
        }

    [[noreturn]] inline void listen( size_t _QueueLength = SOMAXCONN )
        {   // start listening for incoming connections
        _Invoke_socket_func( _LIBSOCK listen,
            static_cast<int>(_QueueLength) );
        }

    template<
        typename _Ty
    > [[noreturn]] inline void connect( _Ty* _Addr, size_t _Addrlen )
        {   // connect to the remote host
        return _Invoke_socket_func( _LIBSOCK connect,
            reinterpret_cast<sockaddr*>(_Addr),
            static_cast<int>(_Addrlen) );
        }

    template<
        typename _SockT
    > _NODISCARD inline _Basic_socket& accept()
        {   // accept incoming connection from the client
        return accept<_SockT, sockaddr>( nullptr, nullptr );
        }

    template<
        typename _SockT, 
        typename _Ty
    > _NODISCARD inline _SockT accept( _Ty* _Addr, size_t* _Addrlen )
        {   // accept incoming connection from the client
        int addrlen = (_Addrlen) ? static_cast<int>(*_Addrlen) : 0;
        _SockT accepted = _Invoke_socket_func( _LIBSOCK accept,
            reinterpret_cast<sockaddr*>(_Addr),
            (_Addrlen) ? &addrlen : nullptr );
        if( _Addrlen != nullptr )
            (*_Addrlen) = static_cast<size_t>(addrlen);
        return accepted;
        }

protected:
    _Socket_handle _Handle;
    address_family _Addr_family;

    inline _Basic_socket( _Socket_handle _Handle = _Invalid_socket ) noexcept
        : _Handle( _Handle )
        {   // construct socket object from existing handle
        }

    template<
        typename _Fx,
        typename... _Ax
    > inline auto _Invoke_socket_func( _Fx&& _Func, _Ax... _Args ) const
        {   // invoke socket function and raise exception on error
        auto result = _Func( _Handle, _Args... );
        _Throw_if_failed( (int)(result) );
        return result;
        }

    template<
        typename _Fx,
        typename... _Ax
    > inline auto _Invoke_socket_func_nothrow( _Fx&& _Func, _Ax... _Args ) const noexcept
        {   // invoke socket function without raising exception on error
        return _Func( _Handle, _Args... );
        }

    [[noreturn]] inline void _Throw_if_failed( int _Retval ) const
        {   // throw exception if _Retval indicates error
        if( _Retval < 0 )
            { // assume that all negative return values indicate error
#       if defined( OS_WINDOWS )
        // Windows OSes provide error data with this function
            _Retval = WSAGetLastError();
#       endif
            throw socket_exception( _Retval );
            }
        }
    };


class isocket
    : public virtual _Basic_socket
    {
public:
    inline isocket( address_family _Family, socket_type _Type, protocol _Protocol )
        : _Basic_socket( _Family, _Type, _Protocol )
        {   // construct input-only socket
        _Invoke_socket_func( _LIBSOCK shutdown, SD_SEND );
        }

    inline virtual int recv( void* _Data, size_t _ByteSize, int _Flags = 0 )
        {   // receive message from the remote host
        if( _ByteSize == 0 ) return 0;
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Data );
        return _Invoke_socket_func( _LIBSOCK recv,
            reinterpret_cast<char*>(_Data),
            static_cast<int>(_ByteSize),
            _Flags );
        }

protected:
    inline isocket( _Socket_handle _Handle = _Invalid_socket ) noexcept
        : _Basic_socket( _Handle )
        {   // construct socket object from existing handle
        }
    };


class osocket
    : public virtual _Basic_socket
    {
public:
    inline osocket( address_family _Family, socket_type _Type, protocol _Protocol )
        : _Basic_socket( _Family, _Type, _Protocol )
        {   // construct output-only socket
        _Invoke_socket_func( _LIBSOCK shutdown, SD_RECEIVE );
        }

    inline virtual int send( const void* _Data, size_t _ByteSize, int _Flags = 0 )
        {   // send message to the remote host
        if( _ByteSize == 0 ) return 0;
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Data );
        return _Invoke_socket_func( _LIBSOCK send,
            reinterpret_cast<const char*>(_Data),
            static_cast<int>(_ByteSize),
            _Flags );
        }

protected:
    inline osocket( _Socket_handle _Handle = _Invalid_socket ) noexcept
        : _Basic_socket( _Handle )
        {   // construct socket object from existing handle
        }
    };


class iosocket
    : public isocket
    , public osocket
    {
public:
    inline iosocket( address_family _Family, socket_type _Type, protocol _Protocol )
        : _Basic_socket( _Family, _Type, _Protocol )
        {   // construct new socket object
        }
    };


template<
    typename _Elem,
    typename _Traits = std::char_traits<_Elem>
> class _Basic_isocketstream
    : virtual public std::basic_istream<_Elem, _Traits>
    {
public:
    typedef std::basic_istream<_Elem, _Traits> _Myistream;

    inline _Basic_isocketstream<_Elem, _Traits>( std::_Uninitialized )
        : _Myistream( std::_Noinit )
        , _Socket( _Invalid_socket )
        {   // construct uninitialized
        }

    inline _Basic_isocketstream<_Elem, _Traits>( isocket& _Socket )
        : _Myistream()
        , _Socket( _Socket )
        {   // construct from existing socket object
        }
    
    _Basic_isocketstream<_Elem, _Traits>( const _Basic_isocketstream<_Elem, _Traits>& ) = delete;
    _Basic_isocketstream<_Elem, _Traits>& operator=( const _Basic_isocketstream<_Elem, _Traits>& ) = delete;

protected:
    isocket& _Socket;
    };

using isocketstream = _Basic_isocketstream<char>;
using iwsocketstream = _Basic_isocketstream<wchar_t>;

}// libsock

#endif// RC_INVOKED
#endif// __libsock_h_
