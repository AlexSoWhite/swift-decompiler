cmake_minimum_required(VERSION 3.23)
project(SwiftDecompiler)

set(CMAKE_CXX_STANDARD 14)

add_executable(SwiftDecompiler main.cpp Finders/Finder.cpp Finders/Finder.h swift)
find_package(LLVM REQUIRED CONFIG)
target_link_libraries(SwiftDecompiler PUBLIC iblessing-core SwiftDemangle LLVMSupport)