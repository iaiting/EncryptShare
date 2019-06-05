project (ccrypto)
print_info()


# 头文件存到变量 HEADERS 中
file (GLOB HEADERS "*.h")


# 头文件存到变量 HEADERS 中
file (GLOB SRCS "*.c")
# aux_source_directory(. SRCS)
message(STATUS ${SRCS})

# 设置生成的库文件目录，这里我们设置成和库目录相同
set (LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 设置可执行文件目录，同样设成和库目录相同
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

add_library ( ${PROJECT_NAME} SHARED ${SRCS} ${HEADERS})

add_subdirectory (test)