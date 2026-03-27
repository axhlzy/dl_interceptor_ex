cmake_minimum_required(VERSION 3.22.1)
project(di_injector LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Paths to the .so files that will be embedded
# These are set by the build script via -D flags
# ---------------------------------------------------------------------------
if(NOT DEFINED DI_INTERCEPTOR_SO)
    message(FATAL_ERROR "DI_INTERCEPTOR_SO not set. Pass -DDI_INTERCEPTOR_SO=<path>")
endif()
if(NOT DEFINED DI_NOTHING_SO)
    message(FATAL_ERROR "DI_NOTHING_SO not set. Pass -DDI_NOTHING_SO=<path>")
endif()

# ---------------------------------------------------------------------------
# Generate hex headers from .so files at configure time
# ---------------------------------------------------------------------------
set(GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${GEN_DIR})

find_package(Python3 REQUIRED COMPONENTS Interpreter)

execute_process(
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/bin2hex.py
        ${DI_INTERCEPTOR_SO} embedded_interceptor_so ${GEN_DIR}/embedded_interceptor.h
    RESULT_VARIABLE rc1
)
execute_process(
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/bin2hex.py
        ${DI_NOTHING_SO} embedded_nothing_so ${GEN_DIR}/embedded_nothing.h
    RESULT_VARIABLE rc2
)
if(NOT rc1 EQUAL 0 OR NOT rc2 EQUAL 0)
    message(FATAL_ERROR "bin2hex.py failed (rc1=${rc1}, rc2=${rc2})")
endif()

# ---------------------------------------------------------------------------
# Build the injector executable
# ---------------------------------------------------------------------------
add_executable(di_injector injector.cpp)

target_compile_features(di_injector PRIVATE cxx_std_17)
target_include_directories(di_injector PRIVATE ${GEN_DIR})
target_compile_options(di_injector PRIVATE
    -Wall -Wextra -Werror
    -Wno-unused-parameter
    -Wno-unused-function
    -Os -ffunction-sections -fdata-sections
    -fPIE
)
target_link_options(di_injector PRIVATE
    -static-libstdc++
    -Wl,--gc-sections
    -fPIE -pie
)
target_link_libraries(di_injector PRIVATE log)

if((${ANDROID_ABI} STREQUAL "arm64-v8a") OR (${ANDROID_ABI} STREQUAL "x86_64"))
    target_link_options(di_injector PRIVATE "-Wl,-z,max-page-size=16384")
endif()
