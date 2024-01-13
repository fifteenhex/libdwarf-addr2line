project('libdwarf-addr2line', 'c')

libdwarf_dep = dependency('libdwarf')
install_headers('addr2line.h')
libdwarf_addr2line = library('dwarf-addr2line', 'libaddr2line.c', dependencies : libdwarf_dep, install: true)
libdwarf_addr2line_dep = declare_dependency(link_with: libdwarf_addr2line)
meson.override_dependency('libdwarf-addr2line', libdwarf_addr2line_dep)

executable('addr2line', 'addr2line.c', dependencies: [libdwarf_dep, libdwarf_addr2line_dep])

