add_library(merge_objects OBJECT
    merge_mega.cpp
)
target_include_directories(merge_objects PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
add_dependencies(merge_objects msgpack-c)