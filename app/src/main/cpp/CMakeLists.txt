cmake_minimum_required(VERSION 3.10.2)


project("bypass_dlfunctions_sample")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")

set(bypass_dlfcn_root_dir ${CMAKE_CURRENT_SOURCE_DIR}/../../../../lib)
add_subdirectory(${bypass_dlfcn_root_dir} bypasss_dlfcn)

add_subdirectory(mini_io)
include_directories(mini_io)

include_directories(
        ${bypass_dlfcn_root_dir}/include/
)


add_library(hello-jnicallback SHARED
        Main_seccomp_64.c
        Main_seccomp.c
        Main_JNI.c
        antiTest.c
        seccommp.h

            )

# Include libraries needed for hello-jnicallback lib
target_link_libraries(hello-jnicallback
                      android
                      bypass_dlfcn
        mini_io
                      log)
