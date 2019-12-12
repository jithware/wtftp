project('wtftp', 'c', version: '0.1.0.1', license : 'GPL2+')
add_project_arguments('-DWTFTP_VERSION="' + meson.project_version() + '"', language : 'c')

# libwtftp
pcap_dep = dependency('pcap')
libnet_dep = dependency('Libnet', cmake_module_path : './CMakeModules')
subdir('lib')

# wapi
have_wapi = false
c = meson.get_compiler('c')
if c.has_header(meson.source_root() + '/wapi/wapi.h')
    netlink_dep = dependency('Netlink', cmake_module_path : './CMakeModules', required : false)
    iwlib_dep = dependency('Iwlib', cmake_module_path : './CMakeModules', required : false)
    libnlgenl3_dep = c.find_library('nl-genl-3', required : false) 
    libm_dep = c.find_library('m', required : false) 
    if netlink_dep.found() and iwlib_dep.found() and libnlgenl3_dep.found() and libm_dep.found()
        have_wapi = true
        subdir('wapi')
    endif
endif

# wtftpd
apr_dep = dependency('Apr', cmake_module_path : './CMakeModules', required : false)
aprutil_dep = dependency('AprUtil', cmake_module_path : './CMakeModules', required : false)
if apr_dep.found() and aprutil_dep.found()
    subdir('wtftpd')
else
    warning('Configured to build without wtftpd')
endif 

