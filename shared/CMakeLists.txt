add_library(lab_shared STATIC
    crypto.c
    policy.c
    protocol.c
    util.c
    third_party/cJSON.c
    third_party/sha256.c
)

target_include_directories(lab_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

if(WIN32)
    target_link_libraries(lab_shared PUBLIC bcrypt ws2_32 advapi32)
endif()
