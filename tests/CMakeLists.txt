set(yara_ttd_STATIC_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(yara_ttd_STATIC_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(test_shellcode
	${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode.c)
add_executable(test_upx
	${CMAKE_CURRENT_SOURCE_DIR}/test_upx.c)

if(MSVC)
	add_definitions(-DWIN32 -DUNICODE -D_UNICODE)
	target_compile_options(test_upx PUBLIC "$<$<CONFIG:DEBUG>:/MTd>" "$<$<CONFIG:DEBUG>:/WX>")
	target_compile_options(test_upx PUBLIC "$<$<CONFIG:RELEASE>:/MT>" "$<$<CONFIG:RELEASE>:/WX>")
	target_compile_options(test_shellcode PUBLIC "$<$<CONFIG:DEBUG>:/MTd>" "$<$<CONFIG:DEBUG>:/WX>")
	target_compile_options(test_shellcode PUBLIC "$<$<CONFIG:RELEASE>:/MT>" "$<$<CONFIG:RELEASE>:/WX>")
endif()
