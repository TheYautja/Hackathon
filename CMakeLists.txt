cmake_minimum_required(VERSION 3.16)
project(LabOrchestrator VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_subdirectory(shared)
add_subdirectory(agent)
add_subdirectory(admin)
