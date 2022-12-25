cmake_minimum_required(VERSION 3.23)
project(SwiftDecompiler)

set(CMAKE_CXX_STANDARD 14)

add_executable(SwiftDecompiler main.cpp swift BinaryReader/BinaryReader.cpp BinaryReader/BinaryReader.h Binary/Binary.cpp Binary/Binary.h)
find_package(LLVM REQUIRED CONFIG)
target_link_libraries(SwiftDecompiler PUBLIC iblessing-core SwiftDemangle LLVMSupport)