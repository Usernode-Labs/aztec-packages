set(BATCH_MERGE_LEAF_VK_BIN "${PROJECT_SOURCE_DIR}/../../crates/aztec-barretenberg-rs/src/data/batch_merge_leaf_vk.bin")
set(BATCH_MERGE_AGG_VK_BIN "${PROJECT_SOURCE_DIR}/../../crates/aztec-barretenberg-rs/src/data/batch_merge_agg_vk.bin")
foreach(ARITY RANGE 3 24)
    set(BATCH_MERGE_LEAF_${ARITY}_VK_BIN "${PROJECT_SOURCE_DIR}/../../crates/aztec-barretenberg-rs/src/data/batch_merge_leaf_${ARITY}_vk.bin")
    set(BATCH_MERGE_AGG_${ARITY}_VK_BIN "${PROJECT_SOURCE_DIR}/../../crates/aztec-barretenberg-rs/src/data/batch_merge_agg_${ARITY}_vk.bin")
endforeach()
set(BATCH_MERGE_EMBEDDED_VKS_HDR "${CMAKE_CURRENT_BINARY_DIR}/batch_merge_embedded_vks.hpp")
set(BATCH_MERGE_VK_GEN_ARGS
    -DLEAF_VK_BIN=${BATCH_MERGE_LEAF_VK_BIN}
    -DAGG_VK_BIN=${BATCH_MERGE_AGG_VK_BIN}
)
set(BATCH_MERGE_VK_DEPS
    "${BATCH_MERGE_LEAF_VK_BIN}"
    "${BATCH_MERGE_AGG_VK_BIN}"
)
foreach(ARITY RANGE 3 24)
    list(APPEND BATCH_MERGE_VK_GEN_ARGS
        -DLEAF_${ARITY}_VK_BIN=${BATCH_MERGE_LEAF_${ARITY}_VK_BIN}
        -DAGG_${ARITY}_VK_BIN=${BATCH_MERGE_AGG_${ARITY}_VK_BIN}
    )
    list(APPEND BATCH_MERGE_VK_DEPS
        "${BATCH_MERGE_LEAF_${ARITY}_VK_BIN}"
        "${BATCH_MERGE_AGG_${ARITY}_VK_BIN}"
    )
endforeach()

add_custom_command(
    OUTPUT "${BATCH_MERGE_EMBEDDED_VKS_HDR}"
    COMMAND
        ${CMAKE_COMMAND}
        ${BATCH_MERGE_VK_GEN_ARGS}
        -DOUT_HDR=${BATCH_MERGE_EMBEDDED_VKS_HDR}
        -P "${PROJECT_SOURCE_DIR}/cmake/generate_batch_merge_vk_header.cmake"
    DEPENDS
        ${BATCH_MERGE_VK_DEPS}
        "${PROJECT_SOURCE_DIR}/cmake/generate_batch_merge_vk_header.cmake"
    VERBATIM
)

add_library(merge_objects OBJECT
    batch_merge.cpp
    "${BATCH_MERGE_EMBEDDED_VKS_HDR}"
)
target_include_directories(merge_objects PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(merge_objects msgpack-c)
