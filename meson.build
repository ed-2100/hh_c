project('hh_c', 'c', version: '0.1',
  default_options : [
    'b_lto=true',
    'b_pie=false',
    'optimization=2',
    'debug=false'
  ]
)

simd_option = get_option('simd')

hh_c_lib_links = []
hh_c_lib_includes = include_directories('include')
hh_c_lib_args = []

if simd_option == 'none'
  hh_c_lib_links += static_library('none', 'src/highwayhash_portable.c', include_directories: hh_c_lib_includes, build_by_default: false)
  hh_c_lib_args += ['-DHIGHWAYHASH_PORTABLE']
elif simd_option == 'avx2'
  hh_c_lib_links += static_library('avx2', 'src/highwayhash_avx2.c', c_args: ['-mavx2'], include_directories: hh_c_lib_includes, build_by_default: false)
endif

# Main library
hh_c_lib = library('hh_c', files('src/highwayhash_common.c'), link_with: hh_c_lib_links, c_args: hh_c_lib_args, include_directories: hh_c_lib_includes)

# Declare dependency
hh_c = declare_dependency(link_with: hh_c_lib, include_directories: hh_c_lib_includes)

# Executable
executable('hh_c_test', 'src/highwayhash_test.c', dependencies: [hh_c], build_by_default: false)
