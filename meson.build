project('hh_c', ['c'], version: '0.1')

hh_c_lib_sources = [
  'src/highwayhash.c'
]

if get_option('simd') == 'none'
    hh_c_lib_sources += 'src/highwayhash_portable.c'
elif get_option('simd') == 'avx2'
    hh_c_lib_sources += 'src/highwayhash_avx2.c'
endif

hh_c_lib = library('hh_c', hh_c_lib_sources, include_directories: include_directories('include'))
hh_c = declare_dependency(link_with: hh_c_lib, include_directories: include_directories('include'))

executable('hh_c_test', 'src/highwayhash_test.c', dependencies: [hh_c], build_by_default : false)
