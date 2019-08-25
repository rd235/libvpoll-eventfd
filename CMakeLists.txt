cmake_minimum_required(VERSION 3.12)
project(vpoll
		VERSION 0.0.1
		DESCRIPTION "generate synthetic events for poll/select/ppoll/pselect/epoll"
		HOMEPAGE_URL "https://github.com/rd235/libvpoll-eventfd")
include(GNUInstallDirs)
add_definitions(-D_GNU_SOURCE)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
if (PROJECT_INCLUDEDIR)
  include_directories(${PROJECT_INCLUDEDIR})
  execute_process(COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/vpoll.h ${PROJECT_INCLUDEDIR}/.)
endif (PROJECT_INCLUDEDIR)

set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

set(VPOLL_SOURCES vpoll.c)
add_library(vpoll SHARED ${VPOLL_SOURCES})
target_link_libraries(vpoll fduserdata)

set_target_properties(vpoll PROPERTIES VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})

set(PROJECT_PC_REQUIRES "fduserdata")
configure_file(vpoll.pc.in vpoll.pc @ONLY)

install(TARGETS vpoll LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES vpoll.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/vpoll.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

add_subdirectory(man)
