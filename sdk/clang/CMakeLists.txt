# step 1: 设置cmake最低版本要求
cmake_minimum_required (VERSION 3.8.0)

# step 2: 指定项目名称和版本，一般和项目的文件夹名称对应
project (SDK VERSION 1.0.0)

# step 3: 包含子目录
add_subdirectory (src/ccrypto)
