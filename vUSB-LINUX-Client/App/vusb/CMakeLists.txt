cmake_minimum_required(VERSION 2.6)
include(CheckIncludeFiles) 
include(CheckLibraryExists) 

project(vusb C)
add_definitions(-O2 -pthread -Wall -Werror -Wextra -std=gnu99)
add_definitions(-DHAVE_CONFIG_H -DUSBIDS_FILE="/usr/share/hwdata//usb.ids")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

add_library(vusblib STATIC 
		libsrc/names.c
		libsrc/ipusb_common.c
		libsrc/ipusb_host_driver.c
		)

add_executable(usbredir
		src/ipusbd.c
		src/ipusb_network.c
		)
target_link_libraries(vusblib sysfs)
target_link_libraries(usbredir vusblib)

install(TARGETS  usbredir
	RUNTIME DESTINATION bin
)

INSTALL(FILES usb.ids
	DESTINATION share/hwdata
	)

