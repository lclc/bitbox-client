include_directories(../include)


#-----------------------------------------------------------------------------
# Build tests_unit
add_executable(tests_unit tests_unit.c)
target_link_libraries(tests_unit ${CMAKE_PROJECT_NAME})
