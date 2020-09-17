CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(krypton VERSION 0.0.1)

SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_STANDARD_REQUIRED True)
SET(CMAKE_CXX_FLAGS "-std=c++17 -Wall -Wextra -Weffc++ -fpermissive -I${CMAKE_SOURCE_DIR}/include")

CONFIGURE_FILE(Config.hpp.in Config.hpp)

INCLUDE_DIRECTORIES(AFTER SYSTEM src include)

ADD_EXECUTABLE(krypton
    "${CMAKE_SOURCE_DIR}/src/main.cpp"
)

TARGET_SOURCES(krypton
    PUBLIC
        "${CMAKE_SOURCE_DIR}/src"
)

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

ENABLE_TESTING()

FIND_PACKAGE(GTest REQUIRED)

IF(GTest_FOUND)
    TARGET_INCLUDE_DIRECTORIES(krypton PUBLIC
        "${GTest_INCLUDE_DIRS}"
    )
    TARGET_LINK_LIBRARIES(krypton PUBLIC
        GTest::GTest
        GTest::Main
    )
ENDIF()
