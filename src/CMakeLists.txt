set(C-SOURCES
    bitbox-client.c
    aes.c
    base64.c
    commander.c
    jsmn.c
    memory.c
    sha2.c
    utils.c
)

include_directories(SYSTEM
                    ${OPENSSL_INCLUDE_DIR}
                    ${HIDAPI_INCLUDE_DIR}
                    ../include
)

add_library(${CMAKE_PROJECT_NAME}
  SHARED
  ${C-SOURCES}
)

target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC ${OPENSSL_LIBRARIES} ${HIDAPI_LIBRARY})

if(NOT WIN32)
  include(GNUInstallDirs)
  install(TARGETS ${CMAKE_PROJECT_NAME}
          DESTINATION ${CMAKE_INSTALL_LIBDIR}
          EXPORT ${CMAKE_PROJECT_NAME}Targets
          COMPONENT main
  )
endif()
