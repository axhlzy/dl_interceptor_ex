cmake_minimum_required(VERSION 3.10)
project(taint_tracker CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(taint_tracker
    main.cpp
    TraceParser.cpp
    TaintEngine.cpp
)
