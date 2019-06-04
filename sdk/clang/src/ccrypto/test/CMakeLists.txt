project (ccryptotest)

aux_source_directory (. SRCS)

add_executable (${PROJECT_NAME} ${SRCS})

# 添加链接库
target_link_libraries(${PROJECT_NAME} ccrypto)