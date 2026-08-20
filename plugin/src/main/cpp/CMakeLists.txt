cmake_minimum_required(VERSION 3.22.1)
project(exitfy_bridge C)

option(EXITFY_BUILD_FAKE_CORES "Build native test cores" OFF)

function(exitfy_enable_flexible_page_sizes target)
    target_link_options(${target} PRIVATE "-Wl,-z,max-page-size=16384")
endfunction()

add_library(exitfy_bridge SHARED exitfy_bridge.c)

target_compile_options(exitfy_bridge PRIVATE
        -Wall
        -Wextra
        -Werror
        -fvisibility=hidden)

target_link_libraries(exitfy_bridge PRIVATE android dl log)
exitfy_enable_flexible_page_sizes(exitfy_bridge)

if(EXITFY_BUILD_FAKE_CORES)
    target_compile_definitions(exitfy_bridge PRIVATE EXITFY_BUILD_FAKE_CORES=1)
    add_library(exitfy_fake_core SHARED fake_core.c)
    add_library(exitfy_fake_core_alt SHARED fake_core.c)
    add_library(exitfy_fake_core_v1 SHARED fake_core_v1.c)
    target_compile_options(exitfy_fake_core PRIVATE -Wall -Wextra -Werror)
    target_compile_options(exitfy_fake_core_alt PRIVATE -Wall -Wextra -Werror)
    target_compile_options(exitfy_fake_core_v1 PRIVATE -Wall -Wextra -Werror)
    exitfy_enable_flexible_page_sizes(exitfy_fake_core)
    exitfy_enable_flexible_page_sizes(exitfy_fake_core_alt)
    exitfy_enable_flexible_page_sizes(exitfy_fake_core_v1)
endif()
