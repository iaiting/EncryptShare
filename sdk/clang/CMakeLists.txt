project (clang)

# 添加include目录，本例头文件在./当前目录下，所以直接取${PROJECT_SOURCE_DIR}/
include_directories (${PROJECT_SOURCE_DIR}/)

# 设置生成的库文件目录，这里我们设置成和库目录相同
set (LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 设置可执行文件目录，同样设成和库目录相同
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)


# 查找当前目录下的所有源文件
# 并将名称保存到 DIR_LIB_SRCS 变量
aux_source_directory(. DIR_LIB_SRCS)

# 生成链接库
add_library (${PROJECT_NAME} SHARED ${DIR_LIB_SRCS})

add_subdirectory (test)