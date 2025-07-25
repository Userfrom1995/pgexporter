cmake_minimum_required(VERSION 3.14)

set(VERSION_MAJOR "0")
set(VERSION_MINOR "7")
set(VERSION_PATCH "0")
set(VERSION_STRING ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

option(ENABLE_COVERAGE "Enable code coverage" OFF)

if (CMAKE_BUILD_TYPE MATCHES Debug)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

#
# Avoid source tree pollution
#
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

If(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds are not permitted. Make a separate folder for building:\nmkdir build; cd build; cmake ..\nBefore that, remove the files already created:\nrm -rf CMakeCache.txt CMakeFiles")
endif(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)

project(pgexporter VERSION ${VERSION_STRING} LANGUAGES  C)

set(CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH})
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME
  "${CMAKE_PROJECT_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
set(CPACK_SOURCE_IGNORE_FILES
  "/build/;/.git/;/.github/;/*.patch;/.bundle/;/_site/;/vendor/;~$;${CPACK_SOURCE_IGNORE_FILES}")
include(CPack)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

message(STATUS "pgexporter ${VERSION_STRING}")

set(generation TRUE)
set(check TRUE)

include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(FindPackageHandleStandardArgs)
include(GNUInstallDirs)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: Debug Release" FORCE)
endif ()

message(STATUS "Build type is ${CMAKE_BUILD_TYPE}")
message(STATUS "System is ${CMAKE_SYSTEM_NAME}")

set(SUPPORTED_COMPILERS "GNU" "Clang" "AppleClang")

# Check for a supported compiler
if (NOT CMAKE_C_COMPILER_ID IN_LIST SUPPORTED_COMPILERS)
   message(FATAL_ERROR "Unsupported compiler ${CMAKE_C_COMPILER_ID}. Supported compilers are: ${SUPPORTED_COMPILERS}")
endif ()

CHECK_C_COMPILER_FLAG("-std=c17" COMPILER_SUPPORTS_C17)
if(NOT COMPILER_SUPPORTS_C17)
  message(FATAL_ERROR "The compiler ${CMAKE_C_COMPILER} has no C17 support. Please use a different C compiler.")
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(HOMEBREW_PREFIX "/opt/homebrew")
  else()
    set(HOMEBREW_PREFIX "/usr/local")
  endif()
  
  message(STATUS "Detected macOS with Homebrew prefix: ${HOMEBREW_PREFIX}")
  
  set(CMAKE_PREFIX_PATH "${HOMEBREW_PREFIX}" ${CMAKE_PREFIX_PATH})
  include_directories("${HOMEBREW_PREFIX}/include")
  link_directories("${HOMEBREW_PREFIX}/lib")
  
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DARWIN_C_SOURCE -I${HOMEBREW_PREFIX}/include")
endif()

find_package(Check)
if (CHECK_FOUND)
  message(STATUS "check found")
  add_library(Check::check SHARED IMPORTED)
  set_target_properties(Check::check PROPERTIES
    IMPORTED_LOCATION ${CHECK_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${CHECK_INCLUDE_DIR})
else ()
  set(check FALSE)
  message(STATUS "check needed. The test suite process will be skipped.")
endif()

find_package(ZLIB)
if (ZLIB_FOUND)
  message(STATUS "zlib found")
else ()
  message(FATAL_ERROR "zlib needed")
endif()

find_package(BZip2)
if (BZIP2_FOUND)
  message(STATUS "bzip2 found")
else ()
  message(FATAL_ERROR "bzip2 needed")
endif()

find_package(Zstd)
if (ZSTD_FOUND)
  message(STATUS "zstd found")
else ()
  message(FATAL_ERROR "zstd needed")
endif()

find_package(Lz4)
if (LZ4_FOUND)
  message(STATUS "lz4 found")
else ()
  message(FATAL_ERROR "lz4 needed")
endif()

find_package(Libev 4.11)
if (LIBEV_FOUND)
  message(STATUS "libev found")
else ()
  message(FATAL_ERROR "libev needed")
endif()

find_package(OpenSSL)
if (OPENSSL_FOUND)
  message(STATUS "OpenSSL found")
else ()
  message(FATAL_ERROR "OpenSSL needed")
endif()

find_package(Rst2man)
if (RST2MAN_FOUND)
  message(STATUS "rst2man found")
else ()
  message(FATAL_ERROR "rst2man needed")
endif()

find_package(THREAD)
if (THREAD_FOUND)
  message(STATUS "pthread found")
else ()
  message(FATAL_ERROR "pthread needed")
endif()

find_package(Pandoc)
if (PANDOC_FOUND)
  message(STATUS "pandoc found")
else ()
  set(generation FALSE)
  message(STATUS "pandoc needed. The generation process will be skipped.")
endif()

find_package(Pdflatex)
if (PDFLATEX_FOUND)
  message(STATUS "pdflatex found")
else ()
  set(generation FALSE)
  message(STATUS "pdflatex needed. The generation process will be skipped.")
endif()

find_package(Doxygen
             REQUIRED dot)
if (DOXYGEN_FOUND)
  message(status "Doxygen found: ${DOXYGEN_EXECUTABLE}")
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  find_package(Libatomic)
  if (LIBATOMIC_FOUND)
    message(STATUS "libatomic found")
  else ()
    message(FATAL_ERROR "libatomic needed")
  endif()

  find_package(Systemd)
  if (SYSTEMD_FOUND)
    message(STATUS "systemd found")
  else ()
    message(STATUS "systemd not found; building without systemd support")
  endif()
endif()

find_package(LibYAML)
if (LIBYAML_FOUND)
  message(STATUS "LibYAML found")
else ()
  message(FATAL_ERROR "LibYAML needed")
endif()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/src/")

add_subdirectory(doc)
add_subdirectory(src)
add_subdirectory(extensions)
add_subdirectory(test)