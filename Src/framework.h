#pragma once

#if defined( _WIN32 ) || defined( _WIN64 ) || defined( WIN32 )

#if __has_include(<sdkddkver.h>)
#include <sdkddkver.h>
#endif

#ifdef _WIN32_WINNT
#define OS_WINDOWS

#include <WinSock2.h>

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

#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif

#elif defined( __POSIX__ )
#define OS_LINUX

#include <sys/socket.h>

#else
#error Unknown target OS

#endif
