cmake_minimum_required(VERSION 2.6)
project(libwireshark-example)
set(CMAKE_BUILD_TYPE Debug)

if(MSVC)
  # Force to always compile with W4
  if(CMAKE_C_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
  endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUC)
  # Update if necessary
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -pedantic -std=c89")
endif()

include_directories(include)
include_directories(.)
include_directories(SYSTEM ~/dl/wireshark)
file(GLOB MAIN1 frame_tvbuff.c main.c)
file(GLOB MAIN2 frame_tvbuff.c main2.c)
add_executable(${PROJECT_NAME}1 ${MAIN1})
add_executable(${PROJECT_NAME}2 ${MAIN2})
add_definitions(-DWS_NORETURN=_Noreturn)

find_package(PkgConfig REQUIRED)
pkg_search_module(LIBWIRESHARK REQUIRED wireshark)

target_link_libraries(${PROJECT_NAME}1 ${LIBWIRESHARK_LIBRARIES})
target_link_libraries(${PROJECT_NAME}2 ${LIBWIRESHARK_LIBRARIES})
target_include_directories(${PROJECT_NAME}1 PUBLIC ${LIBWIRESHARK_INCLUDE_DIRS})
target_include_directories(${PROJECT_NAME}2 PUBLIC ${LIBWIRESHARK_INCLUDE_DIRS})
target_compile_options(${PROJECT_NAME}1 PUBLIC ${LIBWIRESHARK_CFLAGS_OTHER})
target_compile_options(${PROJECT_NAME}2 PUBLIC ${LIBWIRESHARK_CFLAGS_OTHER})

target_link_libraries(${PROJECT_NAME}1 wiretap)
target_link_libraries(${PROJECT_NAME}2 wiretap)
target_link_libraries(${PROJECT_NAME}1 wsutil)
target_link_libraries(${PROJECT_NAME}2 wsutil)

