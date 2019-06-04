project (ccrypto)

aux_source_directory(. DIR_TEST1_SRCS)

add_library ( ${PROJECT_NAME} ${DIR_TEST1_SRCS})

add_subdirectory (test)