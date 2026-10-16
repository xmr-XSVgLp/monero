# Copyright (c) 2026, The Monero Project
# See LICENSE for licensing terms.

monero_add_minimal_executable(trezor_thp_tool thp_tool.cpp)
target_link_libraries(trezor_thp_tool
  PRIVATE
    device_trezor
    cryptonote_basic
    epee
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})
set_property(TARGET trezor_thp_tool PROPERTY FOLDER "tests")
