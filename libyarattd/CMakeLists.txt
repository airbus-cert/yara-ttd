#####################################################
########### Static library use for test #############
#####################################################

set(libyarattd_STATIC_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(libyarattd_STATIC_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# yara_ttd sources
set(libyarattd_SRC
	${libyarattd_STATIC_SRC}/libyarattd_common.c
	${libyarattd_STATIC_SRC}/libyarattd_pe.c
	${libyarattd_STATIC_SRC}/libyarattd_scanner.c
	${libyarattd_STATIC_SRC}/libyarattd_scheduler.c
	${libyarattd_STATIC_SRC}/libyarattd_ttd.c
	${libyarattd_STATIC_SRC}/libyarattd_utils.c
	${libyarattd_STATIC_SRC}/libyarattd_vect.c
	${libyarattd_STATIC_SRC}/libyarattd_virtual_alloc.c
)

set(libyarattd_INCLUDE
	${libyarattd_STATIC_INCLUDE}/libyarattd_common.h	
	${libyarattd_STATIC_INCLUDE}/libyarattd_crypto.h	
	${libyarattd_STATIC_INCLUDE}/libyarattd_pe.h
	${libyarattd_STATIC_INCLUDE}/libyarattd_scanner.h
	${libyarattd_STATIC_INCLUDE}/libyarattd_scheduler.h
	${libyarattd_STATIC_INCLUDE}/libyarattd_ttd.h
	${libyarattd_STATIC_INCLUDE}/libyarattd_ttd_types.h
	${libyarattd_STATIC_INCLUDE}/libyarattd_types.h
	${libyarattd_STATIC_INCLUDE}/libyarattd_utils.h
	${libyarattd_STATIC_INCLUDE}/libyarattd_vect.h
	${libyarattd_STATIC_INCLUDE}/libyarattd_virtual_alloc.h
)

# Create static library
add_library(libyarattd STATIC ${libyarattd_SRC} ${libyarattd_INCLUDE})

# Include directories management
target_include_directories(
	libyarattd 
	PUBLIC $<BUILD_INTERFACE:${libyarattd_STATIC_INCLUDE}> $<INSTALL_INTERFACE:include>
)
target_link_libraries(libyarattd PUBLIC libyara)

if(MSVC)
	add_definitions(-DWIN32 -DUNICODE -D_UNICODE)
	target_compile_options(yara-ttd PUBLIC "$<$<CONFIG:DEBUG>:/MTd>" "$<$<CONFIG:DEBUG>:/WX>")
	target_compile_options(yara-ttd PUBLIC "$<$<CONFIG:RELEASE>:/MT>" "$<$<CONFIG:RELEASE>:/WX>")
endif()

install(TARGETS libyarattd EXPORT yarattd LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
install(DIRECTORY ${libyarattd_SRC_PATH}/include DESTINATION include FILES_MATCHING PATTERN "*.h*")

include(GNUInstallDirs)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/yarattd.pc DESTINATION lib/pkgconfig)
install(EXPORT yarattd DESTINATION cmake)
