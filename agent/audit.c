#include "audit.h"
#include "util.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

void lab_audit_log(const char *event, const char *fmt, ...)
{
    FILE *f = fopen(lab_log_path(), "a");
    va_list ap;
    char detail[512];

    if (!f)
        return;

    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);

    {
        time_t now = (time_t)lab_now_unix();
        struct tm *lt = localtime(&now);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", lt);
        fprintf(f, "[%s] %s | %s\n", ts, event, detail);
    }

    fclose(f);
}
