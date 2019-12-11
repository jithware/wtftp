project('wtftp', 'c', version: '0.1.0.1')
add_project_arguments('-DWTFTP_VERSION="' + meson.project_version() + '"', language : 'c')

pcap_dep = dependency('pcap')
libnet_dep = dependency('Libnet', cmake_module_path : './CMakeModules')
subdir('lib')

apr_dep = dependency('Apr', cmake_module_path : './CMakeModules', required : false, not_found_message: 'Not building wtftpd')
aprutil_dep = dependency('AprUtil', cmake_module_path : './CMakeModules', required : false, not_found_message: 'Not building wtftpd')
if apr_dep.found() and aprutil_dep.found()
    subdir('wtftpd')
endif

