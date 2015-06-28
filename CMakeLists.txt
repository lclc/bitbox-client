cmake_minimum_required(VERSION 2.8)
project(bitbox-client)

find_package(Git)
if(GIT_FOUND)
  execute_process(COMMAND git "rev-parse" "HEAD" OUTPUT_VARIABLE GIT_COMMIT_HASH WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
  set(GIT_COMMIT_HASH "Git not found.")
endif()

set(VERSION_MAJOR  1)
set(VERSION_MINOR  0)
set(VERSION_BUGFIX 0)
set(VERSION_STRING "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_BUGFIX}")

#-----------------------------------------------------------------------------
# Options for building

option(BUILD_VERBOSE       "Verbose build output." ON)
option(BUILD_TESTS         "Build the unit tests." ON)
#option(BUILD_DOCUMENTATION "Build the Doxygen documentation." ON)

option(BUILD_SHARED_LIBS   "Build shared libraries." ON)
option(RPM                 "Build a RPM" OFF)
option(DEB                 "Build a DEB" OFF)
set(PACKAGE_CONTACT        ""                             CACHE <TYPE>  "Package Maintainer")
set(PACKAGE_VENDOR         "Lucas Betschart" CACHE <TYPE>  "Package Vendor")

if(BUILD_VERBOSE)
  set(CMAKE_VERBOSE_MAKEFILE true)
endif()

if(RPM OR DEB)
    if(NOT PACKAGE_CONTACT)
        message(FATAL_ERROR "Specify a PACKAGE_CONTACT to build packages.")
    endif()
endif()


#-----------------------------------------------------------------------------
# Print system information and build options

message(STATUS "General -------------------------------------")
message(STATUS "bitbox-client version:            ${VERSION_STRING}")
message(STATUS "Git Commit Hash:        ${GIT_COMMIT_HASH}")
message(STATUS "CMake version:          ${CMAKE_VERSION}")
message(STATUS "System:                 ${CMAKE_SYSTEM}")
message(STATUS "Processor:              ${CMAKE_SYSTEM_PROCESSOR}")

message(STATUS "Verbose:                ${BUILD_VERBOSE}")
message(STATUS "Testing:                ${BUILD_TESTS}")
#message(STATUS "Documentation:          ${BUILD_DOCUMENTATION}")

message(STATUS "Packaging -----------------------------------")
message(STATUS "Build RPM:              ${RPM}")
message(STATUS "Build DEB:              ${DEB}")
message(STATUS "Package Contact:        ${PACKAGE_CONTACT}")
message(STATUS "Package Vendor:         ${PACKAGE_VENDOR}")


#-----------------------------------------------------------------------------
# Collect all binaries into bin subdirectory

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_CURRENT_BINARY_DIR}/lib)


#-----------------------------------------------------------------------------
# Compiler flags

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W -Wall -Wextra -Werror -Wredundant-decls -Wstrict-prototypes -Wundef -Wshadow -Wpointer-arith -Wmultichar -Wformat-nonliteral -Winit-self -Wformat-security -Wold-style-definition -Wmissing-include-dirs -Wbad-function-cast -Winline -Wnested-externs -Wfloat-equal -Wmissing-declarations -Wswitch-default")

if(APPLE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
  set(CMAKE_MACOSX_RPATH ON)
endif()

#if(${CMAKE_C_COMPILER_ID} MATCHES GNU)
#elseif(${CMAKE_CXX_COMPILER_ID} MATCHES Clang)
#endif()

message(STATUS "C Compiler ID: ${CMAKE_C_COMPILER_ID}")
message(STATUS "C Flags:       ${CMAKE_C_FLAGS}")
message(STATUS "C link flags:  ${CMAKE_C_LINK_FLAGS}")


#-----------------------------------------------------------------------------
# Get submodules

#execute_process(COMMAND git "submodule" "update" "--init" "--recursive" WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})


#-----------------------------------------------------------------------------
# Third party libraries

find_package(OpenSSL REQUIRED)

if(NOT CONTINUOUS_INTEGRATION)
    find_library(HIDAPI_LIBRARY
    NAMES hidapi hidapi-libusb)

    find_path(HIDAPI_INCLUDE_DIR
    NAMES hidapi.h
    PATH_SUFFIXES
    hidapi)

    if(!HIDAPI_FOUND)
    message(FATAL_ERROR "hidapi not found.")
    endif()
endif()


#-----------------------------------------------------------------------------
# Force out-of-source build

if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
message(FATAL_ERROR "CMake generation is not allowed within the source directory!
Remove the CMakeCache.txt file and try again from another folder, e.g.:

   rm CMakeCache.txt
   mkdir build
   cd build
   cmake ..
")
endif()


#-----------------------------------------------------------------------------
# Default to Release build

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif()


#-----------------------------------------------------------------------------
# Build Documentation

#if(BUILD_DOCUMENTATION)
#  set(DOC_GRAPHS "YES" CACHE STRING "Create dependency graphs (needs graphviz)")
#  set(DOC_FULLGRAPHS "NO" CACHE STRING "Create call/callee graphs (large)")
#
#  find_program(DOT_PATH dot)
#
#  if (DOT_PATH STREQUAL "DOT_PATH-NOTFOUND")
#    message("Doxygen: graphviz not found - graphs disabled")
#    set(DOC_GRAPHS "NO")
#  endif()
#
#  find_package(Doxygen)
#  if(DOXYGEN_FOUND)
#    configure_file("cmake/Doxyfile.in" "Doxyfile" @ONLY)
#    configure_file("cmake/Doxygen.extra.css.in" "Doxygen.extra.css" @ONLY)
#    add_custom_target(doc
#      ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
#      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
#      COMMENT "Generating API documentation with Doxygen.." VERBATIM)
#  endif()
#endif()


#-----------------------------------------------------------------------------
# Build source

#Fix RPATH
if(APPLE)
  set(CMAKE_INSTALL_NAME_DIR @rpath)
endif()
if(NOT RPM)
  SET(CMAKE_SKIP_BUILD_RPATH  FALSE)
  if(NOT WIN32)
    include(GNUInstallDirs)
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
  endif()
endif()

add_subdirectory(src)

if(BUILD_TESTS)
  add_subdirectory(tests)
#  add_test(NAME tests_unit COMMAND tests_unit)
  enable_testing()
endif()


if (NOT ANDROID)
#-----------------------------------------------------------------------------
# Produce a cmake-package

include(CMakePackageConfigHelpers)
set(CMAKE_CONFIG_DEST "share/cmake/Modules")
set(BITBOX-CLIENT_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include")

export(TARGETS ${CMAKE_PROJECT_NAME} FILE "${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}Targets.cmake")

configure_package_config_file(
       "cmake/${CMAKE_PROJECT_NAME}Config.cmake.in"
       "${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}Config.cmake"
       INSTALL_DESTINATION ${CMAKE_CONFIG_DEST}
       PATH_VARS BITBOX-CLIENT_INCLUDE_DIRS)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}ConfigVersion.cmake"
  VERSION ${VERSION_STRING}
  COMPATIBILITY AnyNewerVersion)

install(EXPORT ${CMAKE_PROJECT_NAME}Targets
        DESTINATION ${CMAKE_CONFIG_DEST} FILE "${CMAKE_PROJECT_NAME}Targets.cmake")

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}Config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION ${CMAKE_CONFIG_DEST}
        COMPONENT dev)


#-----------------------------------------------------------------------------
# Produce a pkg-config file


if(NOT WIN32)
	configure_file("cmake/${CMAKE_PROJECT_NAME}.pc.in" "${CMAKE_PROJECT_NAME}.pc" @ONLY)
	include(GNUInstallDirs)
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}.pc"
		DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
		COMPONENT main)
endif()


#-----------------------------------------------------------------------------
# Install

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION include
        COMPONENT dev
        FILES_MATCHING PATTERN "*.h"
        )


#-----------------------------------------------------------------------------
# Uninstall
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake)


#-----------------------------------------------------------------------------
# Packaging
set(CPACK_GENERATOR "TGZ")
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)

set(CPACK_PACKAGE_VERSION ${VERSION_STRING})
set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
set(CPACK_PACKAGE_CONTACT ${PACKAGE_CONTACT})
set(CPACK_PACKAGE_VENDOR ${PACKAGE_VENDOR})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Digital Bitbox C client library")
set(CPACK_PACKAGE_DESCRIPTION "Digital Bitbox C client library")

if(RPM)
  set(CPACK_GENERATOR "RPM")
  set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
  set(CPACK_RPM_COMPONENT_INSTALL ON)
  set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ChangeLog")
endif()

if(DEB)
  set(CPACK_GENERATOR "DEB")
  set(CPACK_DEB_COMPONENT_INSTALL ON)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl, libhidapi-dev")
  set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
  set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
  set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "digitalbitbox.com")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER ${PACKAGE_CONTACT})
endif()

include(CPack)
endif (NOT ANDROID)
