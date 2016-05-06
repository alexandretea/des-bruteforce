cmake_minimum_required(VERSION 2.8)

set(PROJECT_NAME "des-bruteforce")

project(${PROJECT_NAME})

include(ExternalProject)
include(CheckIncludeFileCXX)

# find_package()
# include_directories()
# link_directories(${CMAKE_SOURCE_DIR}/)

#set(LIBS
	#${Boost_LIBRARIES}
	#-lpthread
#)

file(GLOB headers
)
set(HEADERS ${headers})

file(GLOB sources
	srcs/*.cpp
)
set(SOURCES ${sources})

add_executable(${PROJECT_NAME} ${HEADERS} ${SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES
                      COMPILE_FLAGS "${CMAKE_CXX_FLAGS} \
-g0 -O3 -D PRODUCTION -O3 -std=c++14 -W -Wall -Wextra -Werror")
target_link_libraries(${PROJECT_NAME} ${LIBS})

add_executable(${PROJECT_NAME}_debug ${HEADERS} ${SOURCES})
set_target_properties(${PROJECT_NAME}_debug PROPERTIES COMPILE_FLAGS
"${CMAKE_CXX_FLAGS} -O0 -g3 -D DEBUG -std=c++14 -W -Wall -Wextra")
target_link_libraries(${PROJECT_NAME} ${LIBS})

# add_executable(${PROJECT_NAME}_asan ${HEADERS} ${SOURCES})
# set_target_properties(${PROJECT_NAME}_asan PROPERTIES COMPILE_FLAGS
#                       "${CMAKE_CXX_FLAGS} -O0 -g3 -D DEBUG -std=c++14 \
# -fsanitize=address -fno-omit-frame-pointer -W -Wall -Wextra")
# target_link_libraries(${PROJECT_NAME}_asan -lasan ${LIBS})
