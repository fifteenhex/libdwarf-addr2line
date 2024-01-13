/*  addr2line.c

The code does not attempt to report details
when an unexpected DW_DLV_NO_ENTRY is received
from libdwarf.  It just silently moves on.
*/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "dwarf.h"
#include "libdwarf.h"
#include "addr2line.h"

#define DW_PR_DUx "llx"
#define DW_PR_DUu "llu"

#define MAX_ADDR_LEN 20
#define BATCHMODE_HEURISTIC 100
#define DWARF5_VERSION  5
#define TRUE 1
#define FALSE 0

static const char *objfile_name = "<none>";

static void
fail_exit(const char *msg) {
    printf("addr2line failure reading %s: %s\n",
        objfile_name,
        msg);
    exit(1);
}

static void
err_handler(Dwarf_Error err, Dwarf_Ptr errarg)
{
    printf("libdwarf error reading %s: %lu %s\n",
        objfile_name,
        (unsigned long)dwarf_errno(err),
        dwarf_errmsg(err));
    if (errarg) {
        printf("Error: errarg is nonnull but it should be null\n");
    }
    printf("Giving up");
    exit(1);
}

static void
print_line(Dwarf_Debug dbg,
    flagsT *flags,
    Dwarf_Line line,
    Dwarf_Addr pc)
{
    char *         linesrc = "??";
    Dwarf_Unsigned lineno = 0;

    if (flags->addresses) {
        printf("%#018" DW_PR_DUx "\n", pc);
    }
    if (line) {
        /*  These never return DW_DLV_NO_ENTRY */
        dwarf_linesrc(line, &linesrc, NULL);
        dwarf_lineno(line, &lineno, NULL);
    }
    printf("%s:%" DW_PR_DUu "\n", linesrc, lineno);
    if (line) {
        dwarf_dealloc(dbg, linesrc, DW_DLA_STRING);
    }
}

char *usagestrings[] = {
"addr2line [ -h] [-a] [-e <objectpath>] [-b] [-n] [address] ...",
"where",
"-a --addresses  Turns on printing of address before",
"    the source line text",
"-e --exe  <path> The the path to the object file to read.",
"    Path defaults to \"a.out\"",
"-b --force-batch The CU address ranges will be looked",
"    up once at the start and the generated table used.",
"-n --force-no-batch The addresses are looked up",
"    independently for each address present.",
"    In certain cases the no-batch will be overridden",
"    and batching used.",
"-h --help  Prints a help message and stops.",
0
};

static void
usage(void)
{
    char **u = usagestrings;

    for( ; *u ; u++) {
        printf("%s\n",*u);
    }
    exit(0);
}

static void
populate_options(int argc, char *argv[], char **objfile,
    flagsT *flags)
{
    int c;
    while (1) {
        int option_index = 0;
        static struct option longopts[] =
            {
            {"addresses", no_argument, 0, 'a'},
            {"exe", required_argument, 0, 'e'},
            {"help", no_argument, 0, 'h'},
            {"force-batch", no_argument, 0, 'b'},
            {"force-no-batch", no_argument, 0, 'n'},
            {0, 0, 0, 0}
            };
        c = getopt_long(argc, argv, "ae:hbn", longopts,
            &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'a':
            flags->addresses = TRUE;
            break;
        case 'e':
            *objfile = optarg;
            break;
        case 'b':
            flags->force_batchmode = TRUE;
            break;
        case 'h':
            usage();
            break;
        case 'n':
            flags->force_nobatchmode = TRUE;
            break;
        case '?':
            break;
        default:
            printf("?? getopt returned character code 0%o ??\n", c);
            break;
        }
    }
}

static char *
get_pc_buf(int argc, char **argv, char *buf,
    Dwarf_Bool do_read_stdin)
{
    if (do_read_stdin) {
        return fgets(buf, MAX_ADDR_LEN, stdin);
    } else {
        if (optind < argc) {
            return argv[optind++];
        } else {
            return NULL;
        }
    }
}

int
main(int argc, char *argv[])
{
    int ret;
    Dwarf_Debug dbg;
    char *objfile = "a.out";
    Dwarf_Bool do_read_stdin = FALSE;
    char buf[MAX_ADDR_LEN];
    char *pc_buf = 0;
    char *endptr = 0;
    lookup_tableT lookup_table;

    flagsT flags = {0};
    populate_options(argc, argv, &objfile, &flags);
    objfile_name = objfile;
    ret = dwarf_addr2line_init_path(objfile, &dbg, err_handler, fail_exit);

    do_read_stdin = (optind >= argc);
    if (! flags.force_nobatchmode &&
        (flags.force_batchmode || do_read_stdin ||
        (argc + BATCHMODE_HEURISTIC) > optind)) {
        flags.batchmode = TRUE;
    }
    if (flags.batchmode) {
        ret = create_lookup_table(dbg, &lookup_table);
        if (ret != DW_DLV_OK) {
            fail_exit("Unable to create lookup table");
        }
    }

    while ((pc_buf = get_pc_buf(argc, argv, buf, do_read_stdin))) {
        Dwarf_Addr pc = strtoull(pc_buf, &endptr, 16);
        Dwarf_Bool is_found = FALSE;

        if (endptr != pc_buf) {
            if (flags.batchmode && lookup_table.table) {
                if (pc >= lookup_table.low &&
                    pc < lookup_table.high) {
                    Dwarf_Line line =
                        lookup_table.table[pc - lookup_table.low];
                    if (line) {
                        print_line(dbg, &flags, line, pc);
                        is_found = TRUE;
                    }
                }
            } else {
                is_found = lookup_pc(dbg, &flags, pc);
            }
        }
        if (! is_found) {
            print_line(dbg, &flags, NULL, pc);
        }
    }
    if (flags.batchmode && lookup_table.table) {
        delete_lookup_table(&lookup_table);
    }
    dwarf_finish(dbg);
    return 0;
}
