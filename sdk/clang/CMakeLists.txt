# step 1: 设置cmake最低版本要求
CMAKE_MINIMUM_REQUIRED(VERSION 3.2)

# step 2: 指定项目的名称，一般和项目的文件夹名称对应
PROJECT (SDK VERSION 1.0.0)


include_directories (third_libs/windows/GmSSL32/include)

link_directories (third_libs/windows/GmSSL32/lib)

# step 3: 包含子目录
ADD_SUBDIRECTORY (src)
