project (cjson_test) 

set(CMAKE_CXX_STANDARD 17)

add_library(cjson cjson.cc)
add_executable(cjson_test test.cpp)
target_link_libraries(cjson_test cjson)