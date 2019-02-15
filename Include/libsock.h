#pragma once
#include <memory>
#include <system_error>

namespace libsock
{

enum class address_family
{
    unknown = -1,   // Unknown
    unspec,         // Unspecified
    local,          // Local to host (pipes, portals)
    inet,           // Internet IP protocol version 4 (IPv4)
    implink,        // ARPANET IMP address
    pup,            // PUP protocols
    chaos,          // MIT CHAOS protocols
    ns,             // XEROX NS protocols
    ipx,            // Novell IPX protocols
    iso,            // ISO protocols
    osi,            // OSI protocols
    ecma,           // European Computer Manufacturers
    datakit,        // DATAKIT protocols
    sna,            // IBM SNA
    decnet,         // DECnet
    dli,            // Direct data link interface
    lat,            // LAT
    hylink,         // NSC Hyperchannel
    appletalk,      // AppleTalk
    netbios,        // NetBIOS-style address
    voiceview,      // VoiceView
    firefox,        // FireFox protocols
    banyan,         // Banyan
    atm,            // Native ATM services
    atmpvc,         // ATM PVCs
    inet6,          // Internet IP protocol version 6 (IPv6)
    cluster,        // Microsoft Wolfpack
    ieee1284_4,     // IEEE 1284.4 WG AF
    ieee802154,     // IEEE 802154 sockets
    irda,           // IrDA
    netdes,         // Network Designers OSI & gateway
    tcnprocess,     // 
    tcnmessage,     //
    iclfxbm,        //
    bluetooth,      // Bluetooth RFCOMM/L2CAP protocols
    link,           //
    hyperv,         //
    infiniband,     // Native InfiniBand address
    isdn,           // mISDN sockets
    xdp,            // XDP sockets
    nfc,            // NFC sockets
    bridge,         // Multiprotocol bridge
    x25,            // Reserved for X.25 project
    ax25,           // Amateur Radio AX.25
    rose,           // Amateur Radio X.25 PLP
    netlink,        // 
    netrom,         // Amateur Radio NET/ROM
    netbeui,        // Reserved for 802.2LLC project
    security,       // Security callback pseudo address family
    key,            // Key management API
    packet,         // Packet family
    ash,            // Ash
    econet,         // Acorn Econet
    rds,            // RDS sockets
    pppox,          // PPPoX sockets
    wanpipe,        // Wanpipe API Sockets
    llc,            // Linux LLC
    mpls,           // MPLS
    can,            // Controller Area Network
    tipc,           // TIPC sockets
    iucv,           // IUCV sockets
    rxrpc,          // RxRPC sockets
    phonet,         // Phonet sockets
    caif,           // CAIF sockets
    algorithm,      // Algorithm sockets
    vsock,          // vSockets
    kcm,            // Kernel Connection Multiplexor
    qipcrtr,        // Qualcomm IPC Router
    smc             //
};

enum class socket_type
{
    unknown = -1,   //
    stream,         //
    datagram,       //
    raw,            //
    rdm,            //
    seqpacket       //
};

enum class protocol
{
    unknown = -1,   //
    hopopts,        //
    icmp,           //
    igmp,           //
    ggp,            //
    ipv4,           //
    st,             //
    tcp,            //
    cbt,            //
    egp,            //
    igp,            //
    pup,            //
    udp,            //
    idp,            //
    rdp,            //
    ipv6,           //
    routing,        //
    fragment,       //
    esp,            //
    ah,             //
    icmpv6,         //
    none,           //
    dstopts,        //
    nd,             //
    iclfxbm,        //
    pim,            //
    pgm,            //
    l2tp,           //
    sctp,           //
    raw             //
};


class socket_exception
    : public std::system_error
{
public:
    socket_exception( int _Errval );
};


class socket
{
public:
    socket( address_family family, socket_type type, protocol proto );

    int bind();
    int listen();
    int connect();
    int accept();
    int send();
    int close();
    int set_opt();
    int get_opt();

protected:
    class impl;
    std::unique_ptr<impl> _Impl;
};

}
