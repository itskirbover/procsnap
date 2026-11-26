cmake_minimum_required(VERSION 3.20)
project(procsnap VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(APPLE)
    message(FATAL_ERROR "procsnap supports Linux and Windows only (macOS is intentionally not supported).")
endif()

add_library(procsnap_core STATIC
    src/core/json.cpp
    src/core/sha256.cpp
    src/core/models.cpp
)

target_include_directories(procsnap_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(procsnap_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(procsnap_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(procsnap_platform STATIC
        src/platform/linux/linux_collector.cpp
    )
    target_link_libraries(procsnap_platform PUBLIC procsnap_core)
    target_compile_options(procsnap_platform PRIVATE -Wall -Wextra -Wpedantic)
elseif(WIN32)
    add_library(procsnap_platform STATIC
        src/platform/windows/windows_collector.cpp
    )
    target_link_libraries(procsnap_platform PUBLIC
        procsnap_core
        iphlpapi
        ws2_32
        wintrust
        crypt32
        advapi32
    )
    if(MSVC)
        target_compile_options(procsnap_platform PRIVATE /W4 /permissive-)
    else()
        target_compile_options(procsnap_platform PRIVATE -Wall -Wextra -Wpedantic)
    endif()
else()
    message(FATAL_ERROR "Unsupported platform: procsnap supports Linux and Windows only.")
endif()

add_library(procsnap_engine STATIC
    src/engine/policy.cpp
    src/engine/diff.cpp
    src/engine/detector.cpp
)
target_link_libraries(procsnap_engine PUBLIC procsnap_core)
if(MSVC)
    target_compile_options(procsnap_engine PRIVATE /W4 /permissive-)
else()
    target_compile_options(procsnap_engine PRIVATE -Wall -Wextra -Wpedantic)
endif()
