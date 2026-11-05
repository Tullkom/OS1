#include <dirent.h>
#include <elf.h>
#include <link.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#define ELF_MAGIC                                                              \
  "\x7f"                                                                       \
  "ELF"
#define LIB_HASH_SIZE 1024

typedef struct lib_stat {
    char *name;
    unsigned long count;
    struct lib_stat *next;
} lib_stat;

static lib_stat *lib_table[LIB_HASH_SIZE];

typedef enum { REPORT_NONE, REPORT_TXT, REPORT_HTML, REPORT_JSON } report_kind;

static FILE *g_report = NULL;
static report_kind g_kind = REPORT_NONE;
static int g_first_json_line = 1;

static unsigned long hash_str(const char *s) {
    unsigned long h = 5381;
    while (*s)
        h = h * 33 + (unsigned char)*s++;
    return h;
}

static void html_esc(FILE *f, const char *s) {
    for (; *s; s++) {
        switch (*s) {
        case '&':
            fputs("&amp;", f);
            break;
        case '<':
            fputs("&lt;", f);
            break;
        case '>':
            fputs("&gt;", f);
            break;
        case '"':
            fputs("&quot;", f);
            break;
        default:
            fputc(*s, f);
        }
    }
}

static void json_esc(FILE *f, const char *s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':
            fputs("\\\"", f);
            break;
        case '\\':
            fputs("\\\\", f);
            break;
        case '\n':
            fputs("\\n", f);
            break;
        case '\r':
            fputs("\\r", f);
            break;
        case '\t':
            fputs("\\t", f);
            break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else          fputc(c, f);
        }
    }
}


static void out(const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    fputs(buf, stdout);

    if (!g_report)
        return;

    switch (g_kind) {
    case REPORT_TXT:
        fputs(buf, g_report);
        break;
    case REPORT_HTML:
        fputs("<div>", g_report);
        html_esc(g_report, buf);
        fputs("</div>\n", g_report);
        break;
    case REPORT_JSON:
        if (!g_first_json_line)
            fputs(",\n", g_report);
        g_first_json_line = 0;
        fputc('"', g_report);
        json_esc(g_report, buf);
        fputc('"', g_report);
        break;
    default:
        break;
    }
}

static int lib_stat_add(const char *name) {
    unsigned long h = hash_str(name) % LIB_HASH_SIZE;
    lib_stat *p = lib_table[h];
    while (p) {
        if (strcmp(p->name, name) == 0) {
            p->count++;
            return 0;
        }
        p = p->next;
    }
    p = malloc(sizeof(*p));
    if (!p)
        return -1;
    p->name = strdup(name);
    if (!p->name) {
        free(p);
        return -1;
    }
    p->count = 1;
    p->next = lib_table[h];
    lib_table[h] = p;
    return 0;
}

static size_t lib_stat_collect(lib_stat ***out_arr) {
    size_t n = 0;
    for (int i = 0; i < LIB_HASH_SIZE; i++)
        for (lib_stat *p = lib_table[i]; p; p = p->next)
            n++;

    lib_stat **arr = malloc(n * sizeof(*arr));
    if (!arr) {
        *out_arr = NULL;
        return 0;
    }

    size_t k = 0;
    for (int i = 0; i < LIB_HASH_SIZE; i++)
        for (lib_stat *p = lib_table[i]; p; p = p->next)
            arr[k++] = p;

    *out_arr = arr;
    return n;
}

static void lib_stat_free_all(void) {
    for (int i = 0; i < LIB_HASH_SIZE; i++) {
        lib_stat *p = lib_table[i];
        while (p) {
            lib_stat *n = p->next;
            free(p->name);
            free(p);
            p = n;
        }
        lib_table[i] = NULL;
    }
}

static int cmp_lib_stat(const void *a, const void *b) {
    const lib_stat *x = *(const lib_stat *const *)a;
    const lib_stat *y = *(const lib_stat *const *)b;
    if (x->count != y->count)
        return (x->count < y->count) ? 1 : -1;
    return strcmp(x->name, y->name);
}

static void usage(FILE *stream) {
    fprintf(stream,
            "bldd [LIBNAME] DIR [report=txt|html|json]\n"
            "\n"
            "  LIBNAME  имя разделяемой библиотеки (например, libc.so)\n"
            "  DIR      каталог для сканирования\n"
            "  report   создание файла отчёта в определённом формате\n"
            "bldd libc.so usr/lib - ищет в Директории usr/lib файлы, использующие libc.so");
}

static int elf_type(char *path) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    unsigned char hdr[EI_NIDENT + 2];
    size_t n = fread(hdr, 1, sizeof(hdr), f);
    fclose(f);

    if (n < sizeof(hdr))
        return -1;
    if (memcmp(hdr, ELF_MAGIC, 4) != 0)
        return -1;

    return (uint16_t)hdr[16] | ((uint16_t)hdr[17] << 8);
}

int has_pt_interp(char *path) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    ElfW(Ehdr) ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fclose(f);
        return -1;
    }

    if (fseek(f, (long)ehdr.e_phoff, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    ElfW(Phdr) phdr;
    for (int i = 0; i < ehdr.e_phnum; ++i) {
        if (fread(&phdr, sizeof(phdr), 1, f) != 1) {
            fclose(f);
            return -1;
        }
        if (phdr.p_type == PT_INTERP) {
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}

typedef int (*needed_cb)(const char *name, void *ud);

static int check_libname_cb(const char *name, void *ud) {
    const char *target = ud;
    size_t n = strlen(target);
    return (strncmp(name, target, n) == 0) ? 1 : 0;
}

static int count_needed_cb(const char *name, void *ud) {
    (void)ud;
    lib_stat_add(name);
    return 0;
}

static int elf_depends(const char *path, needed_cb cb, void *ud) {
    if (!path || !cb)
        return -1;

    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    ElfW(Ehdr) ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fclose(f);
        return -1;
    }

    if (fseek(f, (long)ehdr.e_phoff, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    ElfW(Phdr) phdr;
    ElfW(Off) dyn_off = 0;
    ElfW(Xword) dyn_size = 0;
    int found = 0;

    for (int i = 0; i < ehdr.e_phnum; ++i) {
        if (fread(&phdr, sizeof(phdr), 1, f) != 1) {
            fclose(f);
            return -1;
        }
        if (phdr.p_type == PT_DYNAMIC) {
            dyn_off = phdr.p_offset;
            dyn_size = phdr.p_filesz;
            found = 1;
            break;
        }
    }
    if (!found || dyn_size == 0 || dyn_size % sizeof(ElfW(Dyn)) != 0) {
        fclose(f);
        return 0;
    }

    size_t dyn_count = dyn_size / sizeof(ElfW(Dyn));
    ElfW(Dyn) *dyn = malloc(dyn_size);
    if (!dyn) {
        fclose(f);
        return -1;
    }
    if (fseek(f, (long)dyn_off, SEEK_SET) != 0 ||
            fread(dyn, 1, dyn_size, f) != dyn_size) {
        free(dyn);
        fclose(f);
        return -1;
    }

    ElfW(Addr) strtab_vaddr = 0;
    ElfW(Xword) strtab_size = 0;
    int have_strtab = 0;

    for (size_t i = 0; i < dyn_count; ++i) {
        if (dyn[i].d_tag == DT_NULL)
            break;
        if (dyn[i].d_tag == DT_STRTAB) {
            strtab_vaddr = dyn[i].d_un.d_ptr;
            have_strtab = 1;
        } else if (dyn[i].d_tag == DT_STRSZ)
            strtab_size = dyn[i].d_un.d_val;
    }
    if (!have_strtab || strtab_size == 0) {
        free(dyn);
        fclose(f);
        return 0;
    }

    if (fseek(f, (long)ehdr.e_phoff, SEEK_SET) != 0) {
        free(dyn);
        fclose(f);
        return -1;
    }
    long strtab_off = -1;
    for (int i = 0; i < ehdr.e_phnum; ++i) {
        if (fread(&phdr, sizeof(phdr), 1, f) != 1)
            break;
        if (phdr.p_type != PT_LOAD)
            continue;
        if (strtab_vaddr >= phdr.p_vaddr &&
                strtab_vaddr < phdr.p_vaddr + phdr.p_filesz) {
            strtab_off = (long)(phdr.p_offset + (strtab_vaddr - phdr.p_vaddr));
            break;
        }
    }
    if (strtab_off < 0) {
        free(dyn);
        fclose(f);
        return -1;
    }

    char *buf = malloc(strtab_size + 1);
    if (!buf) {
        free(dyn);
        fclose(f);
        return -1;
    }

    int rc = 0;

    for (size_t i = 0; i < dyn_count; ++i) {
        if (dyn[i].d_tag == DT_NULL)
            break;
        if (dyn[i].d_tag != DT_NEEDED)
            continue;

        size_t offset = dyn[i].d_un.d_val;
        if (offset >= strtab_size)
            continue;

        if (fseek(f, strtab_off + (long)offset, SEEK_SET) != 0)
            continue;
        size_t avail = strtab_size - offset;
        size_t got = fread(buf, 1, avail, f);
        buf[got < avail ? got : avail] = '\0';

        if (buf[0] == '\0')
            continue;

        int r = cb(buf, ud);
        if (r < 0) {
            rc = -1;
            break;
        }
        if (r > 0) {
            rc = r;
            break;
        }
    }

    free(buf);
    free(dyn);
    fclose(f);
    return rc;
}

static const char *machine_name(uint16_t m) {
    switch (m) {
    case EM_386:
        return "i386";
    case EM_X86_64:
        return "x86_64";
    case EM_ARM:
        return "arm";
    case EM_AARCH64:
        return "aarch64";
    default:
        return "unknown";
    }
}

static uint16_t elf_arch(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return EM_NONE;
    ElfW(Ehdr) ehdr;
    uint16_t m = EM_NONE;
    if (fread(&ehdr, sizeof(ehdr), 1, f) == 1 &&
            memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0)
        m = ehdr.e_machine;
    fclose(f);
    return m;
}

static int walk_dir(const char *dirpath, const char *libname, int collecting) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "bldd: невозможно открыть каталог '%s'", dirpath);
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        size_t need = strlen(dirpath) + 1 + strlen(ent->d_name) + 1;
        char *path = malloc(need);
        if (!path) {
            closedir(dir);
            return -1;
        }
        snprintf(path, need, "%s/%s", dirpath, ent->d_name);

        struct stat st;
        if (lstat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                walk_dir(path, libname, collecting);
            } else if (S_ISREG(st.st_mode)) {
                int t = elf_type(path);
                if (t == ET_EXEC || t == ET_DYN) {
                    if (has_pt_interp(path) == 1) {
                        if (collecting) {
                            elf_depends(path, count_needed_cb, NULL);
                        } else {
                            int r = elf_depends(path, check_libname_cb, (void *)libname);
                            if (r > 0)
                                out("%s [%s]\n", path, machine_name(elf_arch(path)));
                        }
                    }
                }
            }
        }

        free(path);
    }

    closedir(dir);
    return 0;
}

static void report_write_header(int argc, char **argv) {
    if (!g_report)
        return;

    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_now);

    switch (g_kind) {
    case REPORT_TXT:
        fprintf(g_report, "# time:    %s\n# command:", ts);
        for (int i = 0; i < argc; i++)
            fprintf(g_report, " %s", argv[i]);
        fputc('\n', g_report);
        break;

    case REPORT_HTML:
        fprintf(g_report,
                "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">"
                "<title>bldd report</title></head><body>\n"
                "<p>time: %s<br>command:", ts);
        for (int i = 0; i < argc; i++) {
            fputc(' ', g_report);
            html_esc(g_report, argv[i]);
        }
        fputs("</p>\n<pre>\n", g_report);
        break;

    case REPORT_JSON:
        fprintf(g_report, "{\n  \"time\": \"%s\",\n  \"command\": \"", ts);
        for (int i = 0; i < argc; i++) {
            if (i) fputc(' ', g_report);
            json_esc(g_report, argv[i]);
        }
        fputs("\",\n  \"lines\": [\n", g_report);
        break;

    default:
        break;
    }
}

static void report_write_footer(void) {
    if (!g_report)
        return;

    switch (g_kind) {
    case REPORT_HTML:
        fputs("</pre>\n</body></html>\n", g_report);
        break;
    case REPORT_JSON:
        if (g_first_json_line)
            fputs("  ]\n}\n", g_report);        /* пустой массив */
        else
            fputs("\n  ]\n}\n", g_report);      /* закрыть последнюю строку */
        break;
    default:
        break;
    }
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 4) {
        usage(stderr);
        return -1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }

    const char *libname = NULL;
    const char *dirpath = NULL;
    int want_report = 0;
    int npos = argc - 1;

    const char *last = argv[argc - 1];
    const char *report_val = NULL;
    if (strncmp(last, "report=", 7) == 0) {
        report_val = last + 7;
        npos--;
    }

    if (npos < 1 || npos > 2) {
        usage(stderr);
        return -1;
    }

    if (npos == 1) {
        dirpath = argv[1];
    } else {
        libname = argv[1];
        dirpath = argv[2];
    }

    char* report_name = "report.txt";
    if (report_val) {
        if (strcmp(report_val, "txt") == 0)        g_kind = REPORT_TXT;
        else if (strcmp(report_val, "html") == 0) {
         g_kind = REPORT_HTML;
         report_name = "report.html";
        }
        else if (strcmp(report_val, "json") == 0) {
         g_kind = REPORT_JSON;
         report_name = "report.json";
        }
        else {
            fprintf(stderr, "bldd: неизвестный формат отчёта '%s'\n", report_val);
            usage(stderr);
            return -1;
        }
        want_report = 1;
    }

    int collecting = (libname == NULL);
    if (want_report) {
        g_report = fopen(report_name, "w");
        if (!g_report) {
            fprintf(stderr, "bldd: не удалось открыть report.txt для записи\n");
            return -1;
        }
        report_write_header(argc, argv);
    }

    if (walk_dir(dirpath, libname, collecting) != 0) {
        report_write_footer();
        if (g_report) fclose(g_report);
        return -1;
    }

    if (collecting) {
        lib_stat **arr = NULL;
        size_t n = lib_stat_collect(&arr);
        if (arr) {
            qsort(arr, n, sizeof(*arr), cmp_lib_stat);
            for (size_t i = 0; i < n; i++)
                out("%s %lu\n", arr[i]->name, arr[i]->count);
            free(arr);
        }
        lib_stat_free_all();
    }

    report_write_footer();

    if (g_report) {
        fclose(g_report);
        g_report = NULL;
    }
    return 0;
}