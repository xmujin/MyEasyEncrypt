cmake_minimum_required(VERSION 4.0)
project(${CMAKE_PROJECT_NAME}Tests LANGUAGES CXX)



find_package(GTest REQUIRED)

add_executable(${PROJECT_NAME} 
    src/test_main.cpp
    src/aes_test.cpp
)
target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC
        GTest::GTest
        ${CMAKE_PROJECT_NAME}
        absl::str_format
)


add_test(
NAME
    ${PROJECT_NAME}
COMMAND
    ${PROJECT_NAME}
)