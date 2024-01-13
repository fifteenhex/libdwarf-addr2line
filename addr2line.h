/* */

#include <libdwarf.h>

typedef struct lookup_table {
    Dwarf_Line *table;
    Dwarf_Line_Context *ctxts;
    int cnt;
    Dwarf_Addr low;
    Dwarf_Addr high;
} lookup_tableT;

typedef struct flags {
    Dwarf_Bool addresses;
    Dwarf_Bool batchmode;
    Dwarf_Bool force_batchmode;
    Dwarf_Bool force_nobatchmode;
} flagsT;

int create_lookup_table(Dwarf_Debug dbg, lookup_tableT *lookup_table);
void delete_lookup_table(lookup_tableT *lookup_table);
Dwarf_Bool lookup_pc(Dwarf_Debug dbg, flagsT *flags, Dwarf_Addr pc);

int dwarf_addr2line_init_path(const char *objfile, Dwarf_Debug *dbg,
		void (*err_handler)(Dwarf_Error err, Dwarf_Ptr errarg),
		void (*fail_exit)(const char *msg));
