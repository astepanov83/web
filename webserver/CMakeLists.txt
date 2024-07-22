project(webserver C CXX)

set(SOURCES
    main.cpp
)

set(HEADERS
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME}
    ${Boost_LIBRARIES}
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

if (WIN32)
    target_link_libraries(${PROJECT_NAME}
        Shell32.lib
        advapi32.lib
        wintrust
        crypt32)
else()
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
    ${Boost_INCLUDE_DIRS}
)

install(
    TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}
    COMPONENT runtime
)
