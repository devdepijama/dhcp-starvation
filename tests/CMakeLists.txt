add_executable (testrunner test.c assertions/assertions.c)
target_include_directories(testrunner PUBLIC . ../common)
target_link_libraries (testrunner PUBLIC common)