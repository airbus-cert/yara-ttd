set(yara_ttd_STATIC_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(yara_ttd_STATIC_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
	add_definitions(-DWIN32 -DUNICODE -D_UNICODE)
endif()

add_executable(test_shellcode
	${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode.c)
add_executable(test_upx
	${CMAKE_CURRENT_SOURCE_DIR}/test_upx.c)
