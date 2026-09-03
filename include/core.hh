// include/core.hh
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <bit>

using byte = uint8_t;
using u32 = uint32_t;

// 实际并没有系统限制，此宏只是用来做其他事情
#if defined(_WIN32) || defined(_WIN64)
#    define OP4_PLATFORM_WIN32
#elif defined(__linux) || defined(__gnu_linux__) || defined(__linux__)
#    define OP4_PLATFORM_LINUX
#    if defined(__ANDROID__)
#        define OP4_PLATFORM_ANDROID
#    endif
#else
#    define OP4_PLATFORM_OTHER
#endif

/**
 * OP4_API      声明在需要导出的函数和类中
 * OP4_LIBRARY  定义此宏就代表需将此项目作为库导出
 */
#ifndef OP4_API
#    ifdef OP4_LIBRARY
#        if defined(OP4_PLATFORM_WIN32)
#            define OP4_API __declspec(dllexport)
#        elif defined(OP4_PLATFORM_LINUX)
#            define OP4_API __attribute__((visibility("protected")))
#        else
#            define OP4_API __attribute__((visibility("default")))
#        endif
#    else
#        if defined(OP4_PLATFORM_WIN32)
#            define OP4_API __declspec(dllimport)
#        else
#            define OP4_API __attribute__((visibility("default")))
#        endif
#    endif
#endif
