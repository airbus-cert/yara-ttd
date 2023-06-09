# Minimum CMake required
cmake_minimum_required(VERSION 3.10)
set(yara_LIBYARA_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/yara/libyara")

set(yara_LIBYARA_INC
	${yara_LIBYARA_SRC_PATH}/include/tlshc/tlsh.h
	${yara_LIBYARA_SRC_PATH}/tlshc/tlsh_impl.h
	${yara_LIBYARA_SRC_PATH}/tlshc/tlsh_util.h
	${yara_LIBYARA_SRC_PATH}/include/yara/ahocorasick.h
	${yara_LIBYARA_SRC_PATH}/include/yara/arena.h
	${yara_LIBYARA_SRC_PATH}/include/yara/atoms.h
	${yara_LIBYARA_SRC_PATH}/include/yara/base64.h
	${yara_LIBYARA_SRC_PATH}/include/yara/bitmask.h
	${yara_LIBYARA_SRC_PATH}/include/yara/compiler.h
	${yara_LIBYARA_SRC_PATH}/include/yara/error.h
	${yara_LIBYARA_SRC_PATH}/include/yara/exec.h
	${yara_LIBYARA_SRC_PATH}/include/yara/exefiles.h
	${yara_LIBYARA_SRC_PATH}/include/yara/filemap.h
	${yara_LIBYARA_SRC_PATH}/include/yara/hash.h
	${yara_LIBYARA_SRC_PATH}/include/yara/integers.h
	${yara_LIBYARA_SRC_PATH}/include/yara/libyara.h
	${yara_LIBYARA_SRC_PATH}/include/yara/limits.h
	${yara_LIBYARA_SRC_PATH}/include/yara/mem.h
	${yara_LIBYARA_SRC_PATH}/include/yara/modules.h
	${yara_LIBYARA_SRC_PATH}/include/yara/notebook.h
	${yara_LIBYARA_SRC_PATH}/include/yara/object.h
	${yara_LIBYARA_SRC_PATH}/include/yara/parser.h
	${yara_LIBYARA_SRC_PATH}/include/yara/proc.h
	${yara_LIBYARA_SRC_PATH}/include/yara/re.h
	${yara_LIBYARA_SRC_PATH}/include/yara/rules.h
	${yara_LIBYARA_SRC_PATH}/include/yara/scan.h
	${yara_LIBYARA_SRC_PATH}/include/yara/scanner.h
	${yara_LIBYARA_SRC_PATH}/include/yara/simple_str.h
	${yara_LIBYARA_SRC_PATH}/include/yara/sizedstr.h
	${yara_LIBYARA_SRC_PATH}/include/yara/stack.h
	${yara_LIBYARA_SRC_PATH}/include/yara/stopwatch.h
	${yara_LIBYARA_SRC_PATH}/include/yara/stream.h
	${yara_LIBYARA_SRC_PATH}/include/yara/strutils.h
	${yara_LIBYARA_SRC_PATH}/include/yara/threading.h
	${yara_LIBYARA_SRC_PATH}/include/yara/types.h
	${yara_LIBYARA_SRC_PATH}/include/yara/utils.h
	${yara_LIBYARA_SRC_PATH}/crypto.h
)

set(yara_LIBYARA_SRC
	${yara_LIBYARA_SRC_PATH}/grammar.y
	${yara_LIBYARA_SRC_PATH}/ahocorasick.c
	${yara_LIBYARA_SRC_PATH}/arena.c
	${yara_LIBYARA_SRC_PATH}/atoms.c
	${yara_LIBYARA_SRC_PATH}/base64.c
	${yara_LIBYARA_SRC_PATH}/bitmask.c
	${yara_LIBYARA_SRC_PATH}/compiler.c
	${yara_LIBYARA_SRC_PATH}/endian.c
	${yara_LIBYARA_SRC_PATH}/exec.c
	${yara_LIBYARA_SRC_PATH}/exefiles.c
	${yara_LIBYARA_SRC_PATH}/filemap.c
	${yara_LIBYARA_SRC_PATH}/hash.c
	${yara_LIBYARA_SRC_PATH}/hex_grammar.y
	${yara_LIBYARA_SRC_PATH}/hex_lexer.l
	${yara_LIBYARA_SRC_PATH}/lexer.l
	${yara_LIBYARA_SRC_PATH}/libyara.c
	${yara_LIBYARA_SRC_PATH}/mem.c
	${yara_LIBYARA_SRC_PATH}/modules.c
	${yara_LIBYARA_SRC_PATH}/notebook.c
	${yara_LIBYARA_SRC_PATH}/object.c
	${yara_LIBYARA_SRC_PATH}/parser.c
	${yara_LIBYARA_SRC_PATH}/proc.c
	${yara_LIBYARA_SRC_PATH}/re.c
	${yara_LIBYARA_SRC_PATH}/re_grammar.y
	${yara_LIBYARA_SRC_PATH}/re_lexer.l
	${yara_LIBYARA_SRC_PATH}/rules.c
	${yara_LIBYARA_SRC_PATH}/scan.c
	${yara_LIBYARA_SRC_PATH}/scanner.c
	${yara_LIBYARA_SRC_PATH}/simple_str.c
	${yara_LIBYARA_SRC_PATH}/sizedstr.c
	${yara_LIBYARA_SRC_PATH}/stack.c
	${yara_LIBYARA_SRC_PATH}/stopwatch.c
	${yara_LIBYARA_SRC_PATH}/strutils.c
	${yara_LIBYARA_SRC_PATH}/stream.c
	${yara_LIBYARA_SRC_PATH}/threading.c
	${yara_LIBYARA_SRC_PATH}/tlshc/tlsh.c
	${yara_LIBYARA_SRC_PATH}/tlshc/tlsh_impl.c
	${yara_LIBYARA_SRC_PATH}/tlshc/tlsh_util.c
	${yara_LIBYARA_SRC_PATH}/lexer.c
	${yara_LIBYARA_SRC_PATH}/hex_lexer.c
	${yara_LIBYARA_SRC_PATH}/grammar.c
	${yara_LIBYARA_SRC_PATH}/re_lexer.c
	${yara_LIBYARA_SRC_PATH}/hex_grammar.c
	${yara_LIBYARA_SRC_PATH}/re_grammar.c
)

set(yara_LIBYARA_MODULES
	${yara_LIBYARA_SRC_PATH}/modules/console/console.c
	${yara_LIBYARA_SRC_PATH}/modules/tests/tests.c
	${yara_LIBYARA_SRC_PATH}/modules/pe/pe.c
	${yara_LIBYARA_SRC_PATH}/modules/elf/elf.c
	${yara_LIBYARA_SRC_PATH}/modules/math/math.c
	${yara_LIBYARA_SRC_PATH}/modules/string/string.c
	${yara_LIBYARA_SRC_PATH}/modules/time/time.c
	${yara_LIBYARA_SRC_PATH}/modules/pe/pe_utils.c
)

# Handle proc
# Actually cmake build system support windows linux and mac
set(yara_LIBYARA_PROC
	${yara_LIBYARA_SRC_PATH}/proc/windows.c
	${yara_LIBYARA_SRC_PATH}/proc/linux.c
	${yara_LIBYARA_SRC_PATH}/proc/mach.c
)

# Create static library
add_library(libyara STATIC ${yara_LIBYARA_SRC} ${yara_LIBYARA_INC} ${yara_LIBYARA_MODULES} ${yara_LIBYARA_PROC})

# Include directories management
target_include_directories(
	libyara 
	PUBLIC $<BUILD_INTERFACE:${yara_LIBYARA_SRC_PATH}/include> $<INSTALL_INTERFACE:include>
	PRIVATE ${yara_LIBYARA_SRC_PATH}
)

# Handle module options build
if(yara_CUCKOO_MODULE)
	target_compile_definitions(libyara PUBLIC CUCKOO_MODULE)
	target_sources(libyara PRIVATE ${yara_LIBYARA_SRC_PATH}/modules/cuckoo.c)
	# link with jansson lib
	include(jansson.cmake)
	target_link_libraries(libyara libjansson)
endif()

if(yara_MAGIC_MODULE AND NOT WIN32)
	target_compile_definitions(libyara PUBLIC MAGIC_MODULE)
	target_sources(libyara PRIVATE ${yara_LIBYARA_SRC_PATH}/modules/magic.c)
	target_link_libraries(libyara magic)
endif()

if(yara_HASH_MODULE)
	target_compile_definitions(libyara PUBLIC HASH_MODULE)
	target_sources(libyara PRIVATE ${yara_LIBYARA_SRC_PATH}/modules/hash.c)
endif()

if(yara_DOTNET_MODULE)
	target_compile_definitions(libyara PUBLIC DOTNET_MODULE)
	target_sources(libyara PRIVATE ${yara_LIBYARA_SRC_PATH}/modules/dotnet.c)
endif()

if(yara_MACHO_MODULE)
	target_compile_definitions(libyara PUBLIC MACHO_MODULE)
	target_sources(libyara PRIVATE ${yara_LIBYARA_SRC_PATH}/modules/macho.c)
endif()

if(yara_DEX_MODULE)
	target_compile_definitions(libyara PUBLIC DEX_MODULE)
	target_sources(libyara PRIVATE ${yara_LIBYARA_SRC_PATH}/modules/dex.c)
endif()

if(WIN32)
	target_compile_definitions(libyara PUBLIC USE_WINDOWS_PROC)
	target_compile_definitions(libyara PUBLIC HAVE_WINCRYPT_H)				# not using openssl
	target_compile_definitions(libyara PUBLIC _CRT_SECURE_NO_WARNINGS) 	# maybe need to correct them
	# need to clean warnings
	target_compile_definitions(libyara PUBLIC
		/wd4005
		/wd4018
		/wd4090
		/wd4146
		/wd4244
		/wd4267
		/wd4996
	)

	target_compile_options(libyara PUBLIC "$<$<CONFIG:DEBUG>:/MTd>")
	target_compile_options(libyara PUBLIC "$<$<CONFIG:RELEASE>:/MT>")
endif()

# Configure TLSH function
add_definitions(-DBUCKETS_128=1)
add_definitions(-DCHECKSUM_1B=1)

install(TARGETS libyara EXPORT yara LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
install(DIRECTORY ${yara_LIBYARA_SRC_PATH}/include DESTINATION include FILES_MATCHING PATTERN "*.h*")

include(GNUInstallDirs)
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/yara.pc.in
#               ${CMAKE_CURRENT_BINARY_DIR}/yara.pc @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/yara.pc DESTINATION lib/pkgconfig)
install(EXPORT yara DESTINATION cmake)
