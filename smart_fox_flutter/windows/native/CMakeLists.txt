cmake_minimum_required(VERSION 3.14)

project(smart_fox_windows_plugin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find WinDivert - it needs to be downloaded separately
# Users need to download WinDivert from https://reqrypt.org/windivert.html
# and place it in the 'windivert' subdirectory
set(WINDIVERT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/windivert")

# Plugin source files
add_library(smart_fox_plugin SHARED
    src/smart_fox_plugin.cpp
    src/sni_service.cpp
    src/packet_injector.cpp
    src/client_hello_maker.cpp
)

# Include directories
target_include_directories(smart_fox_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${WINDIVERT_DIR}/include
)

# Link libraries
target_link_libraries(smart_fox_plugin PRIVATE
    ${WINDIVERT_DIR}/x64/WinDivert.lib
    ws2_32
)

# Windows-specific settings
if(WIN32)
    target_compile_definitions(smart_fox_plugin PRIVATE
        _WIN32_WINNT=0x0601
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

# Flutter plugin requirements
set_target_properties(smart_fox_plugin PROPERTIES
    OUTPUT_NAME "smart_fox_plugin"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Copy WinDivert DLL and SYS files to output
add_custom_command(TARGET smart_fox_plugin POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/x64/WinDivert.dll"
        "${CMAKE_BINARY_DIR}/bin"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/x64/WinDivert64.sys"
        "${CMAKE_BINARY_DIR}/bin"
)
