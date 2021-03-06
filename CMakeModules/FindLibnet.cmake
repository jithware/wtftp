# Locate libnet
# This module defines
# LIBNET_LIBRARIES
# LIBNET_FOUND
# LIBNET_INCLUDE_DIR
#

FIND_PATH(LIBNET_INCLUDE_DIR libnet.h /usr/include C:/msys64/usr/include C:/msys32/usr/include)

FIND_LIBRARY(LIBNET_LIBRARIES NAMES net PATH /usr/lib C:/msys64/usr/lib C:/msys32/usr/lib) 

IF (LIBNET_INCLUDE_DIR AND LIBNET_LIBRARIES)
	SET(LIBNET_FOUND TRUE)
ENDIF (LIBNET_INCLUDE_DIR AND LIBNET_LIBRARIES)


IF (LIBNET_FOUND)
	IF (NOT Libnet_FIND_QUIETLY)
		MESSAGE(STATUS "Found libnet: ${LIBNET_LIBRARIES}")
	ENDIF (NOT Libnet_FIND_QUIETLY)
ELSE (LIBNET_FOUND)
	IF (Libnet_FIND_REQUIRED)
		MESSAGE(FATAL_ERROR "Could not find libnet")
	ENDIF (Libnet_FIND_REQUIRED)
ENDIF (LIBNET_FOUND)

