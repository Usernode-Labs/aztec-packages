set(BATCH_MERGE_LEAF_VK_BIN "${PROJECT_SOURCE_DIR}/../../crates/aztec-barretenberg-rs/src/data/batch_merge_leaf_vk.bin")
set(BATCH_MERGE_AGG_VK_BIN "${PROJECT_SOURCE_DIR}/../../crates/aztec-barretenberg-rs/src/data/batch_merge_agg_vk.bin")
set(BATCH_MERGE_EMBEDDED_VKS_HDR "${CMAKE_CURRENT_BINARY_DIR}/batch_merge_embedded_vks.hpp")

add_custom_command(
    OUTPUT "${BATCH_MERGE_EMBEDDED_VKS_HDR}"
    COMMAND
        ${CMAKE_COMMAND}
        -DLEAF_VK_BIN=${BATCH_MERGE_LEAF_VK_BIN}
        -DAGG_VK_BIN=${BATCH_MERGE_AGG_VK_BIN}
        -DOUT_HDR=${BATCH_MERGE_EMBEDDED_VKS_HDR}
        -P "${PROJECT_SOURCE_DIR}/cmake/generate_batch_merge_vk_header.cmake"
    DEPENDS
        "${BATCH_MERGE_LEAF_VK_BIN}"
        "${BATCH_MERGE_AGG_VK_BIN}"
        "${PROJECT_SOURCE_DIR}/cmake/generate_batch_merge_vk_header.cmake"
    VERBATIM
)

add_library(merge_objects OBJECT
    batch_merge.cpp
    "${BATCH_MERGE_EMBEDDED_VKS_HDR}"
)
target_include_directories(merge_objects PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(merge_objects msgpack-c)
