project (ccryptotest)
print_info()

# aux_source_directory (. SRCS2)
file ( GLOB SRCS *.c *.cpp *.h)

message(STATUS ${SRCS})

add_executable (${PROJECT_NAME} ${SRCS})

# 添加链接库
target_link_libraries(${PROJECT_NAME} ccrypto)