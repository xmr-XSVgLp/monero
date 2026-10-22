# Keep the pinned upstream submodule while shipping the local C++ ownership fixes.
# Applying twice is harmless; unexpected upstream/local changes fail explicitly.
find_package(Git REQUIRED)
set(_rapidjson_patch "${CMAKE_CURRENT_LIST_DIR}/patches/rapidjson-ownership.patch")
set(_rapidjson_dir "${CMAKE_CURRENT_SOURCE_DIR}/external/rapidjson")
execute_process(COMMAND "${GIT_EXECUTABLE}" apply --reverse --check "${_rapidjson_patch}"
  WORKING_DIRECTORY "${_rapidjson_dir}" RESULT_VARIABLE _already_applied
  OUTPUT_QUIET ERROR_QUIET)
if(NOT _already_applied EQUAL 0)
  execute_process(COMMAND "${GIT_EXECUTABLE}" apply --check "${_rapidjson_patch}"
    WORKING_DIRECTORY "${_rapidjson_dir}" RESULT_VARIABLE _can_apply
    OUTPUT_QUIET ERROR_VARIABLE _patch_error)
  if(NOT _can_apply EQUAL 0)
    message(FATAL_ERROR "Cannot apply RapidJSON ownership fixes: ${_patch_error}")
  endif()
  execute_process(COMMAND "${GIT_EXECUTABLE}" apply "${_rapidjson_patch}"
    WORKING_DIRECTORY "${_rapidjson_dir}" RESULT_VARIABLE _apply_result)
  if(NOT _apply_result EQUAL 0)
    message(FATAL_ERROR "Failed to apply RapidJSON ownership fixes")
  endif()
endif()
