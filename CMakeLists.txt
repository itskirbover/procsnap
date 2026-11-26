cmake_minimum_required(VERSION 3.20)
project(procsnap VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(APPLE)
    message(FATAL_ERROR "procsnap supports Linux and Windows only (macOS is intentionally not supported).")
endif()
