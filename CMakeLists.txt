cmake_minimum_required(VERSION 2.6)
set(VPOLL_VERSION_STRING 0.0.1)
set(VPOLL_VERSION_MAJOR 0)
add_definitions(-D_GNU_SOURCE)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(HEADERS_INSTALL_PATH ${CMAKE_INSTALL_PREFIX}/include)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

set(VPOLL_SOURCES vpoll.c)
add_library(vpoll SHARED ${VPOLL_SOURCES})
target_link_libraries(vpoll fduserdata)

set_target_properties(vpoll PROPERTIES VERSION ${VPOLL_VERSION_STRING}
        SOVERSION ${VPOLL_VERSION_MAJOR})

install(TARGETS vpoll LIBRARY DESTINATION lib)
install(FILES vpoll.h DESTINATION ${HEADERS_INSTALL_PATH})

