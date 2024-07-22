cmake_minimum_required(VERSION 3.17)

project(server C CXX)

cmake_policy(SET CMP0071 NEW)
cmake_policy(SET CMP0074 NEW)

set(CMAKE_CXX_STANDARD 20)

if(WIN32)
    add_definitions(-D_SCL_SECURE_NO_WARNINGS -D_CRT_SECURE_NO_WARNINGS -DNOMINMAX -D_WIN32_WINNT=0x601 -D_UNICODE -DUNICODE -DWIN32_LEAN_AND_MEAN)
    add_compile_options(/FS)
else()
    add_definitions(-D__USE_FILE_OFFSET64 -D__USE_LARGEFILE64 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BIT=64)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_definitions(-DBOOST_ALL_NO_LIB)
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED system thread HINTS ${boost_INSTALL_DIR} NO_DEFAULT_PATH)
find_library(MIMETIC_LIB mimetic HINTS ${mimetic_INSTALL_DIR}/lib NO_DEFAULT_PATH)

set(OPENSSL_USE_STATIC_LIBS ON)
set(OPENSSL_ROOT_DIR ${openssl_INSTALL_DIR})
find_package(OpenSSL REQUIRED)

# add_subdirectory(common)
# add_subdirectory(webclient)
add_subdirectory(webserver)
