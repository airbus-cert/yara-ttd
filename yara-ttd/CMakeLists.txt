#####################################################
########### Static library use for test #############
#####################################################

set(yara_ttd_STATIC_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(yara_ttd_STATIC_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# yara_ttd sources
set(yara_ttd_SRC
	${yara_ttd_STATIC_SRC}/args.c
	${yara_ttd_STATIC_SRC}/threading.c
	${yara_ttd_STATIC_SRC}/yara-ttd.c
)

set(yara_ttd_INCLUDE
	${yara_ttd_STATIC_INCLUDE}/args.h
	${yara_ttd_STATIC_INCLUDE}/threading.h
)

add_executable(yara-ttd ${yara_ttd_SRC} ${yara_ttd_INCLUDE})
target_include_directories(yara-ttd PUBLIC ${yara_ttd_STATIC_INCLUDE})
target_link_libraries(yara-ttd PUBLIC libyara)
target_link_libraries(yara-ttd PUBLIC libyarattd)

if(MSVC)
	add_definitions(-DWIN32 -DUNICODE -D_UNICODE)
	target_compile_options(yara-ttd PUBLIC "$<$<CONFIG:DEBUG>:/MTd>" "$<$<CONFIG:DEBUG>:/WX>")
	target_compile_options(yara-ttd PUBLIC "$<$<CONFIG:RELEASE>:/MT>" "$<$<CONFIG:RELEASE>:/WX>")
endif()
