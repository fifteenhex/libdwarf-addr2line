/* */

#include <libdwarf.h>

typedef struct flags {
    Dwarf_Bool addresses;
    Dwarf_Bool batchmode;
    Dwarf_Bool force_batchmode;
    Dwarf_Bool force_nobatchmode;
} flagsT;

Dwarf_Bool libdwarf_addr2line_lookup_pc(Dwarf_Debug dbg, flagsT *flags, Dwarf_Addr pc);
