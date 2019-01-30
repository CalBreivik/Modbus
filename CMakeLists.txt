cmake_minimum_required (VERSION 2.6)
project (Modbus)

set (Modbus_VERSION_MAJOR 1)
set (Modbus_VERSION_MINOR 0)
set (MODBUS_SRC_LIST Modbus_Main.cpp Modbus_Source.cpp)

configure_file (
  "${PROJECT_SOURCE_DIR}/Modbus_Config.h.in"
  "${PROJECT_BINARY_DIR}/Modbus_Config.h"
  )
  
include_directories ("${PROJECT_BINARY_DIR}")

add_executable (Modbus ${MODBUS_SRC_LIST})

install (TARGETS Modbus DESTINATION bin)
install (FILES Initialization.ini DESTINATION bin)

include (InstallRequiredSystemLibraries)
set (CPACK_PACKAGE_VERSION_MAJOR "${Modbus_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${Modbus_VERSION_MINOR}")
include (CPack)