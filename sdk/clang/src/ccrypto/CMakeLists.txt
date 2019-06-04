project (ccrypto)

aux_source_directory(. SRCS1)

# 设置生成的库文件目录，这里我们设置成和库目录相同
set (LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 设置可执行文件目录，同样设成和库目录相同
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

add_library ( ${PROJECT_NAME} SHARED ${SRCS1})

add_subdirectory (test)