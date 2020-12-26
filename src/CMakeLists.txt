add_executable (app main.c)
target_include_directories(app PUBLIC . ../common)
target_link_libraries (app PUBLIC common)