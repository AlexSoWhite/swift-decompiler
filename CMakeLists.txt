cmake_minimum_required(VERSION 3.23)
project(SwiftDecompiler DESCRIPTION "Simple swift decompiler")
include(GNUInstallDirs)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS -O2)

add_library(SwiftDecompiler SHARED swift
        src/SwiftDecompiler.cpp
        include/SwiftDecompiler.h
)
find_package(LLVM REQUIRED CONFIG)
target_link_libraries(SwiftDecompiler PUBLIC iblessing-core SwiftDemangle LLVMSupport)

target_include_directories(${PROJECT_NAME} PRIVATE include)

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER include/SwiftDecompiler.h)

# For access to standard installation directory variables (CMAKE_INSTALL_xDIR).
include(GNUInstallDirs)

# Set library shared object and API header file to install.
install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )
