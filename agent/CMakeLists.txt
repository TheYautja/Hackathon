add_executable(labagent
    main.c
    audit.c
    ipc.c
    enforcement.c
    reset.c
    network.c
    state.c
)

target_link_libraries(labagent PRIVATE lab_shared)

if(WIN32)
    target_compile_definitions(labagent PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(labagent PRIVATE ws2_32 advapi32 user32 shell32)
endif()
