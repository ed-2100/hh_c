project('hh_c', ['c'], version: '0.1')

hh_c_lib = library('hh_c', 'src/highwayhash.c', include_directories: include_directories('include'))
hh_c = declare_dependency(link_with: hh_c_lib, include_directories: include_directories('include'))

executable('hh_c_test', 'src/highwayhash_test.c', dependencies: [hh_c])

