cmake_minimum_required(VERSION 3.16)
project(ThreatAnalyzer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Engine + CLI (threat_analyzer.cpp) and the Crow web dashboard (web_server.cpp).
# Crow and Asio are header-only and vendored in third_party/.
add_executable(threat_analyzer src/threat_analyzer.cpp src/web_server.cpp)
target_compile_definitions(threat_analyzer PRIVATE TA_VERSION="${PROJECT_VERSION}" ASIO_STANDALONE CROW_DISABLE_STATIC_DIR)
target_include_directories(threat_analyzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/crow/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio/include)
find_package(Threads REQUIRED)
target_link_libraries(threat_analyzer PRIVATE Threads::Threads)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(threat_analyzer PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(threat_analyzer PRIVATE /W4 /utf-8 /permissive- /Zc:__cplusplus)
endif()

if(WIN32)
    target_compile_definitions(threat_analyzer PRIVATE
        _WIN32_WINNT=0x0601 WINVER=0x0601 UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(threat_analyzer PRIVATE iphlpapi advapi32 shell32 wintrust ws2_32 mswsock)
    if(MINGW)  # static runtime: the exe runs without MSYS2 DLLs on PATH
        target_link_options(threat_analyzer PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
endif()

# Copy the rule database and the web front-end next to the executable.
add_custom_command(TARGET threat_analyzer POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/rules $<TARGET_FILE_DIR:threat_analyzer>/rules
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/web $<TARGET_FILE_DIR:threat_analyzer>/web)

# Tests: ctest --output-on-failure
enable_testing()
set(R --rules ${CMAKE_CURRENT_SOURCE_DIR}/rules/signatures.txt --no-color)
set(S ${CMAKE_CURRENT_SOURCE_DIR}/samples)
add_test(NAME selftest      COMMAND threat_analyzer selftest)
add_test(NAME scan_samples  COMMAND threat_analyzer scan ${S} ${R})
add_test(NAME logs_auth     COMMAND threat_analyzer logs ${S}/auth.log ${R})
add_test(NAME logs_web      COMMAND threat_analyzer logs ${S}/access.log ${R})
add_test(NAME logs_firewall COMMAND threat_analyzer logs ${S}/pfirewall.log ${R})
set_tests_properties(scan_samples  PROPERTIES PASS_REGULAR_EXPRESSION "shadow copy deletion")
set_tests_properties(logs_auth     PROPERTIES PASS_REGULAR_EXPRESSION "Successful login after brute force")
set_tests_properties(logs_web      PROPERTIES PASS_REGULAR_EXPRESSION "SQL injection attempt")
set_tests_properties(logs_firewall PROPERTIES PASS_REGULAR_EXPRESSION "Port scan")
