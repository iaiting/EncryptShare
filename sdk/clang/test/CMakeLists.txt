project (clangTest)

include_directories ("${PROJECT_SOURCE_DIR}")

aux_source_directory (. SRC_CLANG_TEST)

add_executable (${PROJECT_NAME} ${SRC_CLANG_TEST})