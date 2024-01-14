project('hh_c', 'c', version: '0.1')

simd_option = get_option('simd')

hh_c_lib_links = []
hh_c_lib_includes = include_directories('include')

if simd_option == 'none'
    hh_c_lib_links += static_library('none', 'src/highwayhash_portable.c', include_directories: hh_c_lib_includes)
elif simd_option == 'avx2'
    hh_c_lib_links += static_library('avx2', 'src/highwayhash_avx2.c', c_args: ['-mavx2'], include_directories: hh_c_lib_includes)
endif

# Main library
hh_c_lib = library('hh_c', files('src/highwayhash.c'), link_with: hh_c_lib_links, include_directories: hh_c_lib_includes)

# Declare dependency
hh_c = declare_dependency(link_with: hh_c_lib, include_directories: hh_c_lib_includes)

# Executable
executable('hh_c_test', 'src/highwayhash_test.c', dependencies: [hh_c], build_by_default: false)
