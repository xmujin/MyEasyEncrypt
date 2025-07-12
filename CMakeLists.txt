cmake_minimum_required(VERSION 4.0)
project(MyEasyEcrypt VERSION 0.1.0 LANGUAGES CXX)



option(${PROJECT_NAME}_ENABLE_UNIT_TESTING "为单元测试启动测试(从'test'子文件夹)." ON)



add_library(${PROJECT_NAME} src/aes.cpp)

target_include_directories(${PROJECT_NAME}
    PUBLIC 
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)


if(${PROJECT_NAME}_ENABLE_UNIT_TESTING)
  enable_testing()
  message(STATUS "为这个项目构建单元测试. 测试应当在test文件夹下\n")
  add_subdirectory(test)
endif()