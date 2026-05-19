cmake_minimum_required(VERSION 3.10)
project(smart_fox_linux VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(NETFILTER REQUIRED libnetfilter_queue)

# Source files
set(SOURCES
    src/smart_fox_plugin.cpp
    src/tun_device.cpp
    src/sni_service.cpp
    src/packet_processor.cpp
    src/client_hello_maker.cpp
)

# Header files
set(HEADERS
    include/smart_fox_plugin.h
    include/tun_device.h
    include/sni_service.h
    include/packet_processor.h
    include/client_hello_maker.h
)

# Create shared library
add_library(smart_fox_native SHARED ${SOURCES} ${HEADERS})

target_include_directories(smart_fox_native PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${NETFILTER_INCLUDE_DIRS}
)

target_link_libraries(smart_fox_native PRIVATE
    ${NETFILTER_LIBRARIES}
    pthread
    cap
)

target_compile_options(smart_fox_native PRIVATE
    -Wall
    -Wextra
    -fPIC
    ${NETFILTER_CFLAGS_OTHER}
)

# Install rules
install(TARGETS smart_fox_native
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# Copy to Flutter build output
add_custom_command(TARGET smart_fox_native POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:smart_fox_native>
        ${CMAKE_CURRENT_SOURCE_DIR}/../build/linux/libsmart_fox_native.so
    COMMENT "Copying library to Flutter build directory"
)
