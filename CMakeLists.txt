cmake_minimum_required(VERSION 2.8)

set(PROJECT_NAME "des-bruteforce")

project(${PROJECT_NAME})

include(ExternalProject)
include(CheckIncludeFileCXX)

include_directories(
    vendors/cxxopts/src
    srcs/classes
    srcs/utils
)
# link_directories(${CMAKE_SOURCE_DIR}/)

set(LIBS
    -lpthread
    -lcrypt
)

# file(GLOB headers
    # vendors/cpp-optparse/*.h
# )
# set(HEADERS ${headers})

file(GLOB sources
	srcs/*.cpp
	srcs/classes/*.cpp
)
set(SOURCES ${sources})

add_executable(${PROJECT_NAME} ${SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES
                      COMPILE_FLAGS "${CMAKE_CXX_FLAGS} \
-g0 -O3 -D PRODUCTION -O3 -std=c++14 -W -Wall -Wextra")
target_link_libraries(${PROJECT_NAME} ${LIBS})

add_executable(${PROJECT_NAME}_debug ${SOURCES})
set_target_properties(${PROJECT_NAME}_debug PROPERTIES COMPILE_FLAGS
"${CMAKE_CXX_FLAGS} -O0 -g3 -D DEBUG -std=c++14 -W -Wall -Wextra")
target_link_libraries(${PROJECT_NAME}_debug ${LIBS})
