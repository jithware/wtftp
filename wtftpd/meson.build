lib_inc = include_directories('../lib')
executable('wtftpd', 'wtftpd.c', link_with : libwtftp, dependencies : [pcap_dep, libnet_dep, apr_dep, aprutil_dep], include_directories : [lib_inc])