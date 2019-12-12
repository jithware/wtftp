include = ['../lib']
link = [libwtftp]
depends = [apr_dep, aprutil_dep]
if have_wapi
    message('Configured to build wtftpd with wireless configuration')
    include += '..'
    link += libwapi
    cargs = '-DHAVE_WAPI'
    executable('wtftpd', 'wtftpd.c', link_with : link, dependencies : depends, include_directories : include, c_args : cargs)
else
    warning('Configured to build wtftpd without wireless configuration')
    executable('wtftpd', 'wtftpd.c', link_with : link, dependencies : depends, include_directories : include)
endif
