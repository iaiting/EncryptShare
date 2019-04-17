project (clang)

# 添加include目录，本例头文件在./当前目录下，所以直接取${PROJECT_SOURCE_DIR}/
include_directories (${PROJECT_SOURCE_DIR}/)


# 把当前文件夹下的源码列表（文件后缀匹配的那些文件）存到变量 SRCS 中
file( GLOB SRCS *.c *.cpp *.cc *.h *.hpp )

# 设置生成的库文件目录，这里我们设置成和库目录相同
set (LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 设置可执行文件目录，同样设成和库目录相同
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 生成链接库
add_library (${PROJECT_NAME} SHARED ${SRCS})


# set_target_properties (${PROJECT_NAME} PROPERTIES LINK_FLAGS "${LINK_FLAGS}" ARCHIVE_OUTPUT_DIRECTORY "${OUT_PATH}")
target_link_libraries (${PROJECT_NAME} libcrypto.lib)

# 测试
add_subdirectory (test)