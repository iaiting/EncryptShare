project (clangTest)

file ( GLOB SRCS *.c *.cpp *.cc *.h *.hpp )

add_executable (${PROJECT_NAME} ${SRCS})

target_link_libraries( ${PROJECT_NAME} clang )