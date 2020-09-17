CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(krypton VERSION 0.0.1)

SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_STANDARD_REQUIRED True)
SET(CMAKE_CXX_FLAGS "-std=c++17 -Wall -Wextra -Weffc++ -fpermissive")

CONFIGURE_FILE(Config.hpp.in Config.hpp)

ADD_EXECUTABLE(krypton main.cpp)

FIND_PACKAGE(Boost 1.72 REQUIRED COMPONENTS filesystem program_options)

IF(Boost_FOUND)
    TARGET_INCLUDE_DIRECTORIES(krypton PUBLIC
        "${PROJECT_BINARY_DIR}"
        "${Boost_INCLUDE_DIRS}"
    )
    TARGET_LINK_LIBRARIES(krypton PUBLIC
        Boost::filesystem
        Boost::program_options
    )
ENDIF()

