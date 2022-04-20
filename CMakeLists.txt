project(HelloWorld C CXX)
cmake_minimum_required(VERSION 3.0)

find_package(OpenSSL REQUIRED)
add_executable(hello_world
    main.cpp
    print.c
    sm4_demo.c
)
target_link_libraries(hello_world PRIVATE OpenSSL::Crypto)
