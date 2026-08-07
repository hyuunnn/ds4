#include "ds4_mcp.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DS4_MCP_MAX_SERVERS 32
#define DS4_MCP_MAX_TOOLS 512
#define DS4_MCP_MAX_ENV 64
#define DS4_MCP_MAX_ARGS 64
#define DS4_MCP_IO_TIMEOUT_MS 30000
#define DS4_MCP_MAX_MSG (16 * 1024 * 1024)

/* ============================================================================
 * Small utilities
 * ============================================================================
 */

typedef struct {
    char *ptr;
    size_t len;
    size_t cap;
} mcp_buf;

static void *mcp_xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) {
        perror("ds4_mcp: malloc");
        exit(1);
    }
    return p;
}

static char *mcp_xstrdup(const char *s) {
    if (!s) s = "";
    size_t n = strlen(s);
    char *p = mcp_xmalloc(n + 1);
    memcpy(p, s, n + 1);
    return p;
}

static void mcp_buf_append(mcp_buf *b, const char *s, size_t n) {
    if (!n) return;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 4096;
        while (cap < b->len + n + 1) cap *= 2;
        char *p = realloc(b->ptr, cap);
        if (!p) {
            perror("ds4_mcp: realloc");
            exit(1);
        }
        b->ptr = p;
        b->cap = cap;
    }
    memcpy(b->ptr + b->len, s, n);
    b->len += n;
    b->ptr[b->len] = '\0';
}

static void mcp_buf_puts(mcp_buf *b, const char *s) {
    if (s) mcp_buf_append(b, s, strlen(s));
}

static void mcp_buf_printf(mcp_buf *b, const char *fmt, ...) {
    char stack[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(stack, sizeof(stack), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof(stack)) {
        mcp_buf_append(b, stack, (size_t)n);
        return;
    }
    char *heap = mcp_xmalloc((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(heap, (size_t)n + 1, fmt, ap);
    va_end(ap);
    mcp_buf_append(b, heap, (size_t)n);
    free(heap);
}

static char *mcp_buf_take(mcp_buf *b) {
    if (!b->ptr) return mcp_xstrdup("");
    char *p = b->ptr;
    b->ptr = NULL;
    b->len = b->cap = 0;
    return p;
}

static void mcp_set_err(char *err, size_t err_len, const char *fmt, ...) {
    if (!err || err_len == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

/* ============================================================================
 * Minimal JSON helpers (string-key lookups; no full DOM)
 * ============================================================================
 */

static char *mcp_json_quote(const char *s) {
    mcp_buf b = {0};
    mcp_buf_puts(&b, "\"");
    if (!s) s = "";
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
        case '"': mcp_buf_puts(&b, "\\\""); break;
        case '\\': mcp_buf_puts(&b, "\\\\"); break;
        case '\b': mcp_buf_puts(&b, "\\b"); break;
        case '\f': mcp_buf_puts(&b, "\\f"); break;
        case '\n': mcp_buf_puts(&b, "\\n"); break;
        case '\r': mcp_buf_puts(&b, "\\r"); break;
        case '\t': mcp_buf_puts(&b, "\\t"); break;
        default:
            if (c < 0x20) mcp_buf_printf(&b, "\\u%04x", c);
            else mcp_buf_append(&b, (const char *)&c, 1);
            break;
        }
    }
    mcp_buf_puts(&b, "\"");
    return mcp_buf_take(&b);
}

static int mcp_hex4(const char *p) {
    int v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        int x;
        if (c >= '0' && c <= '9') x = c - '0';
        else if (c >= 'a' && c <= 'f') x = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') x = c - 'A' + 10;
        else return -1;
        v = (v << 4) | x;
    }
    return v;
}

static void mcp_utf8_append(mcp_buf *b, unsigned code) {
    char out[4];
    if (code <= 0x7f) {
        out[0] = (char)code;
        mcp_buf_append(b, out, 1);
    } else if (code <= 0x7ff) {
        out[0] = (char)(0xc0 | (code >> 6));
        out[1] = (char)(0x80 | (code & 0x3f));
        mcp_buf_append(b, out, 2);
    } else if (code <= 0xffff) {
        out[0] = (char)(0xe0 | (code >> 12));
        out[1] = (char)(0x80 | ((code >> 6) & 0x3f));
        out[2] = (char)(0x80 | (code & 0x3f));
        mcp_buf_append(b, out, 3);
    } else {
        out[0] = (char)(0xf0 | (code >> 18));
        out[1] = (char)(0x80 | ((code >> 12) & 0x3f));
        out[2] = (char)(0x80 | ((code >> 6) & 0x3f));
        out[3] = (char)(0x80 | (code & 0x3f));
        mcp_buf_append(b, out, 4);
    }
}

static char *mcp_json_parse_string_at(const char *q, const char **endp) {
    if (!q || *q != '"') return NULL;
    q++;
    mcp_buf b = {0};
    while (*q && *q != '"') {
        if (*q != '\\') {
            mcp_buf_append(&b, q++, 1);
            continue;
        }
        q++;
        switch (*q) {
        case '"': mcp_buf_append(&b, "\"", 1); q++; break;
        case '\\': mcp_buf_append(&b, "\\", 1); q++; break;
        case '/': mcp_buf_append(&b, "/", 1); q++; break;
        case 'b': mcp_buf_append(&b, "\b", 1); q++; break;
        case 'f': mcp_buf_append(&b, "\f", 1); q++; break;
        case 'n': mcp_buf_append(&b, "\n", 1); q++; break;
        case 'r': mcp_buf_append(&b, "\r", 1); q++; break;
        case 't': mcp_buf_append(&b, "\t", 1); q++; break;
        case 'u': {
            int v = mcp_hex4(q + 1);
            if (v < 0) {
                free(b.ptr);
                return NULL;
            }
            q += 5;
            if (v >= 0xd800 && v <= 0xdbff && q[0] == '\\' && q[1] == 'u') {
                int lo = mcp_hex4(q + 2);
                if (lo >= 0xdc00 && lo <= 0xdfff) {
                    unsigned code = 0x10000 + (((unsigned)v - 0xd800) << 10) +
                                    ((unsigned)lo - 0xdc00);
                    mcp_utf8_append(&b, code);
                    q += 6;
                    break;
                }
            }
            mcp_utf8_append(&b, (unsigned)v);
            break;
        }
        default:
            if (*q) mcp_buf_append(&b, q++, 1);
            break;
        }
    }
    if (*q != '"') {
        free(b.ptr);
        return NULL;
    }
    if (endp) *endp = q + 1;
    return mcp_buf_take(&b);
}

/* Skip one complete JSON value starting at p.  Returns pointer past it, or NULL. */
static const char *mcp_json_skip_value(const char *p) {
    if (!p) return NULL;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == '"') {
        const char *end = NULL;
        char *s = mcp_json_parse_string_at(p, &end);
        free(s);
        return s ? end : NULL;
    }
    if (*p == '{' || *p == '[') {
        char open = *p;
        char close = open == '{' ? '}' : ']';
        int depth = 1;
        bool in_str = false;
        bool esc = false;
        p++;
        while (*p && depth > 0) {
            char c = *p++;
            if (in_str) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') in_str = false;
                continue;
            }
            if (c == '"') in_str = true;
            else if (c == open) depth++;
            else if (c == close) depth--;
        }
        return depth == 0 ? p : NULL;
    }
    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        if (*p == '-') p++;
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') {
            p++;
            while (*p >= '0' && *p <= '9') p++;
        }
        if (*p == 'e' || *p == 'E') {
            p++;
            if (*p == '+' || *p == '-') p++;
            while (*p >= '0' && *p <= '9') p++;
        }
        return p;
    }
    if (!strncmp(p, "true", 4)) return p + 4;
    if (!strncmp(p, "false", 5)) return p + 5;
    if (!strncmp(p, "null", 4)) return p + 4;
    return NULL;
}

/* Find object member value for key at the top level of json object text. */
static const char *mcp_json_obj_get(const char *json, const char *key,
                                    const char **val_end) {
    if (!json || !key) return NULL;
    const char *p = json;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '{') return NULL;
    p++;
    size_t key_len = strlen(key);
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == '}') return NULL;
        if (*p != '"') return NULL;
        const char *k_end = NULL;
        char *k = mcp_json_parse_string_at(p, &k_end);
        if (!k) return NULL;
        p = k_end;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != ':') {
            free(k);
            return NULL;
        }
        p++;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        const char *v_start = p;
        const char *v_end = mcp_json_skip_value(p);
        if (!v_end) {
            free(k);
            return NULL;
        }
        bool match = strlen(k) == key_len && !strcmp(k, key);
        free(k);
        if (match) {
            if (val_end) *val_end = v_end;
            return v_start;
        }
        p = v_end;
    }
    return NULL;
}

static char *mcp_json_get_string(const char *json, const char *key) {
    const char *end = NULL;
    const char *v = mcp_json_obj_get(json, key, &end);
    if (!v) return NULL;
    while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') v++;
    if (*v != '"') return NULL;
    return mcp_json_parse_string_at(v, NULL);
}

static bool mcp_json_get_bool(const char *json, const char *key, bool def) {
    const char *end = NULL;
    const char *v = mcp_json_obj_get(json, key, &end);
    if (!v) return def;
    while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') v++;
    if (!strncmp(v, "true", 4)) return true;
    if (!strncmp(v, "false", 5)) return false;
    return def;
}

static char *mcp_json_slice(const char *start, const char *end) {
    if (!start || !end || end < start) return mcp_xstrdup("");
    size_t n = (size_t)(end - start);
    char *p = mcp_xmalloc(n + 1);
    memcpy(p, start, n);
    p[n] = '\0';
    return p;
}

static bool mcp_json_id_matches(const char *json, int id) {
    const char *end = NULL;
    const char *v = mcp_json_obj_get(json, "id", &end);
    if (!v) return false;
    while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') v++;
    return atoi(v) == id;
}

static bool mcp_json_has_error(const char *json) {
    const char *end = NULL;
    const char *v = mcp_json_obj_get(json, "error", &end);
    if (!v) return false;
    while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') v++;
    return strncmp(v, "null", 4) != 0;
}

static char *mcp_json_error_message(const char *json) {
    const char *end = NULL;
    const char *err = mcp_json_obj_get(json, "error", &end);
    if (!err) return NULL;
    char *msg = mcp_json_get_string(err, "message");
    if (msg) return msg;
    return mcp_json_slice(err, end);
}

/* Extract raw result object/value text from a JSON-RPC response. */
static char *mcp_json_get_result_raw(const char *json) {
    const char *end = NULL;
    const char *v = mcp_json_obj_get(json, "result", &end);
    if (!v) return NULL;
    return mcp_json_slice(v, end);
}

/* ============================================================================
 * Server / tool structures
 * ============================================================================
 */

typedef struct {
    char *key;
    char *value;
} mcp_env;

typedef struct {
    char *name;
    char *command;
    char **args;
    int argc;
    mcp_env *env;
    int envc;
    bool disabled;
    /* runtime */
    pid_t pid;
    int stdin_fd;
    int stdout_fd;
    int next_id;
    mcp_buf rx;
    bool use_content_length; /* set after first framed message, else NDJSON */
    bool framed_known;
    bool connected;
    char *server_title; /* initialize result serverInfo.name if any */
} mcp_server;

typedef struct {
    char *server_name;
    char *tool_name;
    char *exposed_name; /* server__tool */
    char *description;
    char *input_schema_json; /* raw JSON object text for inputSchema */
} mcp_tool;

struct ds4_mcp {
    char *config_path;
    mcp_server *servers;
    int server_count;
    mcp_tool *tools;
    int tool_count;
    ds4_mcp_confirm_fn confirm;
    void *confirm_privdata;
    ds4_mcp_log_fn log;
    void *log_privdata;
    ds4_mcp_cancel_fn cancel;
    void *cancel_privdata;
    bool auto_approve;
    bool connected;
    pthread_mutex_t mu;
};

static void mcp_log(ds4_mcp *mcp, const char *fmt, ...) {
    if (!mcp || !mcp->log) return;
    char stack[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(stack, sizeof(stack), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof(stack)) {
        mcp->log(mcp->log_privdata, stack);
        return;
    }
    char *heap = mcp_xmalloc((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(heap, (size_t)n + 1, fmt, ap);
    va_end(ap);
    mcp->log(mcp->log_privdata, heap);
    free(heap);
}

static bool mcp_cancel(ds4_mcp *mcp) {
    return mcp && mcp->cancel && mcp->cancel(mcp->cancel_privdata);
}

/* Stop a live process and drop runtime I/O state, keeping config fields. */
static void mcp_server_shutdown_runtime(mcp_server *s) {
    if (!s) return;
    free(s->rx.ptr);
    s->rx.ptr = NULL;
    s->rx.len = s->rx.cap = 0;
    free(s->server_title);
    s->server_title = NULL;
    if (s->stdin_fd >= 0) {
        close(s->stdin_fd);
        s->stdin_fd = -1;
    }
    if (s->stdout_fd >= 0) {
        close(s->stdout_fd);
        s->stdout_fd = -1;
    }
    if (s->pid > 0) {
        kill(s->pid, SIGTERM);
        int status = 0;
        for (int i = 0; i < 20; i++) {
            pid_t r = waitpid(s->pid, &status, WNOHANG);
            if (r == s->pid || (r < 0 && errno == ECHILD)) break;
            usleep(50 * 1000);
        }
        if (waitpid(s->pid, &status, WNOHANG) == 0) {
            kill(s->pid, SIGKILL);
            waitpid(s->pid, &status, 0);
        }
        s->pid = -1;
    }
    s->connected = false;
    s->framed_known = false;
    s->use_content_length = false;
    s->next_id = 1;
}

static void mcp_server_clear(mcp_server *s) {
    if (!s) return;
    mcp_server_shutdown_runtime(s);
    free(s->name);
    free(s->command);
    for (int i = 0; i < s->argc; i++) free(s->args[i]);
    free(s->args);
    for (int i = 0; i < s->envc; i++) {
        free(s->env[i].key);
        free(s->env[i].value);
    }
    free(s->env);
    memset(s, 0, sizeof(*s));
    s->stdin_fd = -1;
    s->stdout_fd = -1;
    s->pid = -1;
}

static void mcp_tool_clear(mcp_tool *t) {
    if (!t) return;
    free(t->server_name);
    free(t->tool_name);
    free(t->exposed_name);
    free(t->description);
    free(t->input_schema_json);
    memset(t, 0, sizeof(*t));
}

/* ============================================================================
 * Config parsing
 *
 * Accepts either:
 *   { "mcpServers": { "demo": { "command": "...", "args": [...], "env": {...} } } }
 * or a bare map of servers at the root (same shape as Claude Desktop without
 * the mcpServers wrapper).
 * ============================================================================
 */

static bool mcp_is_ident_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}

static bool mcp_valid_server_name(const char *name) {
    if (!name || !name[0]) return false;
    for (const char *p = name; *p; p++) {
        if (!mcp_is_ident_char(*p)) return false;
    }
    return true;
}

static int mcp_parse_string_array(const char *arr, char ***out_v, int *out_n,
                                  char *err, size_t err_len) {
    *out_v = NULL;
    *out_n = 0;
    if (!arr) return 0;
    const char *p = arr;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '[') {
        mcp_set_err(err, err_len, "expected JSON array");
        return -1;
    }
    p++;
    char **v = NULL;
    int n = 0, cap = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == ']') break;
        if (*p != '"') {
            mcp_set_err(err, err_len, "args entries must be strings");
            for (int i = 0; i < n; i++) free(v[i]);
            free(v);
            return -1;
        }
        const char *end = NULL;
        char *s = mcp_json_parse_string_at(p, &end);
        if (!s) {
            mcp_set_err(err, err_len, "invalid string in args");
            for (int i = 0; i < n; i++) free(v[i]);
            free(v);
            return -1;
        }
        p = end;
        if (n + 1 > cap) {
            cap = cap ? cap * 2 : 8;
            char **nv = realloc(v, (size_t)cap * sizeof(char *));
            if (!nv) {
                free(s);
                for (int i = 0; i < n; i++) free(v[i]);
                free(v);
                mcp_set_err(err, err_len, "out of memory");
                return -1;
            }
            v = nv;
        }
        if (n >= DS4_MCP_MAX_ARGS) {
            free(s);
            for (int i = 0; i < n; i++) free(v[i]);
            free(v);
            mcp_set_err(err, err_len, "too many args (max %d)", DS4_MCP_MAX_ARGS);
            return -1;
        }
        v[n++] = s;
    }
    *out_v = v;
    *out_n = n;
    return 0;
}

static int mcp_parse_env_object(const char *obj, mcp_env **out_v, int *out_n,
                                char *err, size_t err_len) {
    *out_v = NULL;
    *out_n = 0;
    if (!obj) return 0;
    const char *p = obj;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '{') {
        mcp_set_err(err, err_len, "env must be a JSON object");
        return -1;
    }
    p++;
    mcp_env *v = NULL;
    int n = 0, cap = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == '}') break;
        if (*p != '"') {
            mcp_set_err(err, err_len, "invalid env object");
            for (int i = 0; i < n; i++) {
                free(v[i].key);
                free(v[i].value);
            }
            free(v);
            return -1;
        }
        const char *k_end = NULL;
        char *k = mcp_json_parse_string_at(p, &k_end);
        if (!k) {
            mcp_set_err(err, err_len, "invalid env key");
            for (int i = 0; i < n; i++) {
                free(v[i].key);
                free(v[i].value);
            }
            free(v);
            return -1;
        }
        p = k_end;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != ':') {
            free(k);
            mcp_set_err(err, err_len, "invalid env object");
            for (int i = 0; i < n; i++) {
                free(v[i].key);
                free(v[i].value);
            }
            free(v);
            return -1;
        }
        p++;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != '"') {
            free(k);
            mcp_set_err(err, err_len, "env values must be strings");
            for (int i = 0; i < n; i++) {
                free(v[i].key);
                free(v[i].value);
            }
            free(v);
            return -1;
        }
        const char *v_end = NULL;
        char *val = mcp_json_parse_string_at(p, &v_end);
        if (!val) {
            free(k);
            mcp_set_err(err, err_len, "invalid env value");
            for (int i = 0; i < n; i++) {
                free(v[i].key);
                free(v[i].value);
            }
            free(v);
            return -1;
        }
        p = v_end;
        if (n + 1 > cap) {
            cap = cap ? cap * 2 : 8;
            mcp_env *nv = realloc(v, (size_t)cap * sizeof(mcp_env));
            if (!nv) {
                free(k);
                free(val);
                for (int i = 0; i < n; i++) {
                    free(v[i].key);
                    free(v[i].value);
                }
                free(v);
                mcp_set_err(err, err_len, "out of memory");
                return -1;
            }
            v = nv;
        }
        if (n >= DS4_MCP_MAX_ENV) {
            free(k);
            free(val);
            for (int i = 0; i < n; i++) {
                free(v[i].key);
                free(v[i].value);
            }
            free(v);
            mcp_set_err(err, err_len, "too many env vars (max %d)", DS4_MCP_MAX_ENV);
            return -1;
        }
        v[n].key = k;
        v[n].value = val;
        n++;
    }
    *out_v = v;
    *out_n = n;
    return 0;
}

static int mcp_add_server_from_obj(ds4_mcp *mcp, const char *name,
                                   const char *obj, char *err, size_t err_len) {
    if (!mcp_valid_server_name(name)) {
        mcp_set_err(err, err_len, "invalid MCP server name: %s", name ? name : "");
        return -1;
    }
    if (mcp->server_count >= DS4_MCP_MAX_SERVERS) {
        mcp_set_err(err, err_len, "too many MCP servers (max %d)", DS4_MCP_MAX_SERVERS);
        return -1;
    }
    for (int i = 0; i < mcp->server_count; i++) {
        if (!strcmp(mcp->servers[i].name, name)) {
            mcp_set_err(err, err_len, "duplicate MCP server name: %s", name);
            return -1;
        }
    }

    char *command = mcp_json_get_string(obj, "command");
    if (!command || !command[0]) {
        free(command);
        mcp_set_err(err, err_len, "server %s: missing command", name);
        return -1;
    }

    const char *args_end = NULL;
    const char *args_start = mcp_json_obj_get(obj, "args", &args_end);
    char **args = NULL;
    int argc = 0;
    if (args_start) {
        char *args_raw = mcp_json_slice(args_start, args_end);
        if (mcp_parse_string_array(args_raw, &args, &argc, err, err_len) != 0) {
            free(args_raw);
            free(command);
            return -1;
        }
        free(args_raw);
    }

    const char *env_end = NULL;
    const char *env_start = mcp_json_obj_get(obj, "env", &env_end);
    mcp_env *env = NULL;
    int envc = 0;
    if (env_start) {
        char *env_raw = mcp_json_slice(env_start, env_end);
        if (mcp_parse_env_object(env_raw, &env, &envc, err, err_len) != 0) {
            free(env_raw);
            free(command);
            for (int i = 0; i < argc; i++) free(args[i]);
            free(args);
            return -1;
        }
        free(env_raw);
    }

    bool disabled = mcp_json_get_bool(obj, "disabled", false);

    if (!mcp->servers) {
        mcp->servers = mcp_xmalloc(DS4_MCP_MAX_SERVERS * sizeof(mcp_server));
        memset(mcp->servers, 0, DS4_MCP_MAX_SERVERS * sizeof(mcp_server));
    }
    mcp_server *s = &mcp->servers[mcp->server_count++];
    memset(s, 0, sizeof(*s));
    s->name = mcp_xstrdup(name);
    s->command = command;
    s->args = args;
    s->argc = argc;
    s->env = env;
    s->envc = envc;
    s->disabled = disabled;
    s->stdin_fd = -1;
    s->stdout_fd = -1;
    s->pid = -1;
    s->next_id = 1;
    return 0;
}

static int mcp_parse_servers_object(ds4_mcp *mcp, const char *obj,
                                    char *err, size_t err_len) {
    const char *p = obj;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '{') {
        mcp_set_err(err, err_len, "mcpServers must be a JSON object");
        return -1;
    }
    p++;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == '}') break;
        if (*p != '"') {
            mcp_set_err(err, err_len, "invalid mcpServers object");
            return -1;
        }
        const char *k_end = NULL;
        char *name = mcp_json_parse_string_at(p, &k_end);
        if (!name) {
            mcp_set_err(err, err_len, "invalid server name in config");
            return -1;
        }
        p = k_end;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != ':') {
            free(name);
            mcp_set_err(err, err_len, "invalid mcpServers object");
            return -1;
        }
        p++;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        const char *v_start = p;
        const char *v_end = mcp_json_skip_value(p);
        if (!v_end || *v_start != '{') {
            free(name);
            mcp_set_err(err, err_len, "server %s config must be an object", name);
            return -1;
        }
        char *server_obj = mcp_json_slice(v_start, v_end);
        int rc = mcp_add_server_from_obj(mcp, name, server_obj, err, err_len);
        free(server_obj);
        free(name);
        if (rc != 0) return -1;
        p = v_end;
    }
    return 0;
}

bool ds4_mcp_parse_config_text(const char *json, ds4_mcp *mcp,
                               char *err, size_t err_len) {
    if (!json || !mcp) {
        mcp_set_err(err, err_len, "null config");
        return false;
    }
    /* Prefer mcpServers wrapper when present. */
    const char *servers_end = NULL;
    const char *servers = mcp_json_obj_get(json, "mcpServers", &servers_end);
    if (servers) {
        char *obj = mcp_json_slice(servers, servers_end);
        int rc = mcp_parse_servers_object(mcp, obj, err, err_len);
        free(obj);
        return rc == 0;
    }
    /* Fall back to treating the root object as the server map. */
    return mcp_parse_servers_object(mcp, json, err, err_len) == 0;
}

/* ============================================================================
 * Public pure helpers
 * ============================================================================
 */

char *ds4_mcp_exposed_name(const char *server, const char *tool) {
    if (!server) server = "";
    if (!tool) tool = "";
    size_t n = strlen(server) + 2 + strlen(tool) + 1;
    char *out = mcp_xmalloc(n);
    snprintf(out, n, "%s__%s", server, tool);
    return out;
}

bool ds4_mcp_split_exposed_name(const char *exposed, char *server, size_t server_len,
                                char *tool, size_t tool_len) {
    if (!exposed || !server || !tool || server_len == 0 || tool_len == 0)
        return false;
    const char *sep = strstr(exposed, "__");
    if (!sep || sep == exposed || !sep[2]) return false;
    size_t sn = (size_t)(sep - exposed);
    if (sn + 1 > server_len) return false;
    memcpy(server, exposed, sn);
    server[sn] = '\0';
    if (strlen(sep + 2) + 1 > tool_len) return false;
    snprintf(tool, tool_len, "%s", sep + 2);
    return server[0] && tool[0];
}

char *ds4_mcp_build_args_json(const char *const *names,
                              const char *const *values,
                              const bool *is_string,
                              int n) {
    mcp_buf b = {0};
    mcp_buf_puts(&b, "{");
    for (int i = 0; i < n; i++) {
        if (!names[i] || !names[i][0]) continue;
        if (b.len > 1) mcp_buf_puts(&b, ",");
        char *qk = mcp_json_quote(names[i]);
        mcp_buf_puts(&b, qk);
        free(qk);
        mcp_buf_puts(&b, ":");
        if (is_string && is_string[i]) {
            char *qv = mcp_json_quote(values[i] ? values[i] : "");
            mcp_buf_puts(&b, qv);
            free(qv);
        } else {
            const char *v = values[i] && values[i][0] ? values[i] : "null";
            /* Non-string tool args are already JSON text (numbers/bools/objects). */
            mcp_buf_puts(&b, v);
        }
    }
    mcp_buf_puts(&b, "}");
    return mcp_buf_take(&b);
}

/* ============================================================================
 * Transport: Content-Length framing + NDJSON fallback
 * ============================================================================
 */

static int mcp_set_nonblock(int fd, bool on) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    int next = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(fd, F_SETFL, next);
}

static int mcp_write_all(int fd, const char *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                if (poll(&pfd, 1, DS4_MCP_IO_TIMEOUT_MS) <= 0) return -1;
                continue;
            }
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int mcp_server_send(mcp_server *s, const char *json, char *err, size_t err_len) {
    if (!s || s->stdin_fd < 0) {
        mcp_set_err(err, err_len, "MCP server not connected");
        return -1;
    }
    size_t n = strlen(json);
    /* Prefer Content-Length framing (MCP stdio standard). */
    char header[64];
    int hlen = snprintf(header, sizeof(header),
                        "Content-Length: %zu\r\n\r\n", n);
    if (hlen < 0 || (size_t)hlen >= sizeof(header)) {
        mcp_set_err(err, err_len, "MCP framing header failed");
        return -1;
    }
    if (mcp_write_all(s->stdin_fd, header, (size_t)hlen) != 0 ||
        mcp_write_all(s->stdin_fd, json, n) != 0)
    {
        mcp_set_err(err, err_len, "MCP write failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int mcp_server_read_more(mcp_server *s, int timeout_ms, char *err, size_t err_len) {
    if (s->stdout_fd < 0) {
        mcp_set_err(err, err_len, "MCP server stdout closed");
        return -1;
    }
    struct pollfd pfd = { .fd = s->stdout_fd, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr < 0) {
        if (errno == EINTR) return 0;
        mcp_set_err(err, err_len, "MCP poll failed: %s", strerror(errno));
        return -1;
    }
    if (pr == 0) return 0;
    char tmp[8192];
    for (;;) {
        ssize_t n = read(s->stdout_fd, tmp, sizeof(tmp));
        if (n > 0) {
            if (s->rx.len + (size_t)n > DS4_MCP_MAX_MSG) {
                mcp_set_err(err, err_len, "MCP message too large");
                return -1;
            }
            mcp_buf_append(&s->rx, tmp, (size_t)n);
            continue;
        }
        if (n == 0) {
            mcp_set_err(err, err_len, "MCP server closed stdout");
            return -1;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        mcp_set_err(err, err_len, "MCP read failed: %s", strerror(errno));
        return -1;
    }
    return 1;
}

/* Try to extract one complete message from the receive buffer. */
static char *mcp_server_take_message(mcp_server *s) {
    if (!s->rx.ptr || s->rx.len == 0) return NULL;

    /* Content-Length framing */
    if (!strncmp(s->rx.ptr, "Content-Length:", 15) ||
        !strncmp(s->rx.ptr, "content-length:", 15) ||
        strstr(s->rx.ptr, "\nContent-Length:") ||
        strstr(s->rx.ptr, "\ncontent-length:"))
    {
        /* Find header end. */
        char *hdr_end = strstr(s->rx.ptr, "\r\n\r\n");
        size_t sep_len = 4;
        if (!hdr_end) {
            hdr_end = strstr(s->rx.ptr, "\n\n");
            sep_len = 2;
        }
        if (!hdr_end) return NULL;

        long content_len = -1;
        const char *line = s->rx.ptr;
        while (line < hdr_end) {
            const char *nl = strstr(line, "\r\n");
            size_t line_sep = 2;
            if (!nl || nl > hdr_end) {
                nl = strchr(line, '\n');
                line_sep = 1;
            }
            if (!nl || nl > hdr_end) break;
            if (!strncasecmp(line, "Content-Length:", 15)) {
                content_len = strtol(line + 15, NULL, 10);
            }
            line = nl + line_sep;
        }
        if (content_len < 0 || content_len > DS4_MCP_MAX_MSG) return NULL;
        size_t header_total = (size_t)(hdr_end - s->rx.ptr) + sep_len;
        if (s->rx.len < header_total + (size_t)content_len) return NULL;
        char *msg = mcp_xmalloc((size_t)content_len + 1);
        memcpy(msg, s->rx.ptr + header_total, (size_t)content_len);
        msg[content_len] = '\0';
        size_t remain = s->rx.len - header_total - (size_t)content_len;
        memmove(s->rx.ptr, s->rx.ptr + header_total + (size_t)content_len, remain);
        s->rx.len = remain;
        s->rx.ptr[s->rx.len] = '\0';
        s->use_content_length = true;
        s->framed_known = true;
        return msg;
    }

    /* NDJSON: one JSON object per line. */
    char *nl = memchr(s->rx.ptr, '\n', s->rx.len);
    if (!nl) return NULL;
    size_t line_len = (size_t)(nl - s->rx.ptr);
    /* Trim CR */
    size_t trim = line_len;
    if (trim > 0 && s->rx.ptr[trim - 1] == '\r') trim--;
    /* Skip blank lines */
    if (trim == 0) {
        size_t remain = s->rx.len - line_len - 1;
        memmove(s->rx.ptr, s->rx.ptr + line_len + 1, remain);
        s->rx.len = remain;
        s->rx.ptr[s->rx.len] = '\0';
        return mcp_server_take_message(s);
    }
    char *msg = mcp_xmalloc(trim + 1);
    memcpy(msg, s->rx.ptr, trim);
    msg[trim] = '\0';
    size_t remain = s->rx.len - line_len - 1;
    memmove(s->rx.ptr, s->rx.ptr + line_len + 1, remain);
    s->rx.len = remain;
    s->rx.ptr[s->rx.len] = '\0';
    s->use_content_length = false;
    s->framed_known = true;
    return msg;
}

static char *mcp_server_recv_matching(ds4_mcp *mcp, mcp_server *s, int id,
                                      int timeout_ms, char *err, size_t err_len) {
    double deadline = (double)time(NULL) + (timeout_ms / 1000.0) + 1.0;
    for (;;) {
        if (mcp_cancel(mcp)) {
            mcp_set_err(err, err_len, "interrupted");
            return NULL;
        }
        char *msg = mcp_server_take_message(s);
        if (msg) {
            /* Notifications / unmatched messages are discarded for v1. */
            if (mcp_json_id_matches(msg, id)) return msg;
            free(msg);
            continue;
        }
        double now = (double)time(NULL);
        if (now >= deadline) {
            mcp_set_err(err, err_len, "MCP request timed out");
            return NULL;
        }
        int wait_ms = (int)((deadline - now) * 1000.0);
        if (wait_ms < 50) wait_ms = 50;
        if (wait_ms > 1000) wait_ms = 1000;
        if (mcp_server_read_more(s, wait_ms, err, err_len) < 0) return NULL;
    }
}

static char *mcp_rpc(ds4_mcp *mcp, mcp_server *s, const char *method,
                     const char *params_json, char *err, size_t err_len) {
    int id = s->next_id++;
    mcp_buf req = {0};
    char *qmethod = mcp_json_quote(method);
    mcp_buf_printf(&req, "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":%s",
                   id, qmethod);
    free(qmethod);
    if (params_json && params_json[0]) {
        mcp_buf_puts(&req, ",\"params\":");
        mcp_buf_puts(&req, params_json);
    } else {
        mcp_buf_puts(&req, ",\"params\":{}");
    }
    mcp_buf_puts(&req, "}");
    char *wire = mcp_buf_take(&req);
    mcp_log(mcp, "mcp %s -> %s", s->name, method);
    if (mcp_server_send(s, wire, err, err_len) != 0) {
        free(wire);
        return NULL;
    }
    free(wire);
    char *resp = mcp_server_recv_matching(mcp, s, id, DS4_MCP_IO_TIMEOUT_MS,
                                          err, err_len);
    if (!resp) return NULL;
    if (mcp_json_has_error(resp)) {
        char *em = mcp_json_error_message(resp);
        mcp_set_err(err, err_len, "MCP %s error: %s", method,
                    em ? em : "unknown error");
        free(em);
        free(resp);
        return NULL;
    }
    return resp;
}

static int mcp_notify(ds4_mcp *mcp, mcp_server *s, const char *method,
                      const char *params_json, char *err, size_t err_len) {
    (void)mcp;
    mcp_buf req = {0};
    char *qmethod = mcp_json_quote(method);
    mcp_buf_printf(&req, "{\"jsonrpc\":\"2.0\",\"method\":%s", qmethod);
    free(qmethod);
    if (params_json && params_json[0]) {
        mcp_buf_puts(&req, ",\"params\":");
        mcp_buf_puts(&req, params_json);
    }
    mcp_buf_puts(&req, "}");
    char *wire = mcp_buf_take(&req);
    int rc = mcp_server_send(s, wire, err, err_len);
    free(wire);
    return rc;
}

/* ============================================================================
 * Spawn / initialize / tools.list
 * ============================================================================
 */

static int mcp_server_spawn(ds4_mcp *mcp, mcp_server *s, char *err, size_t err_len) {
    int in_pipe[2] = { -1, -1 };
    int out_pipe[2] = { -1, -1 };
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
        mcp_set_err(err, err_len, "pipe failed: %s", strerror(errno));
        if (in_pipe[0] >= 0) close(in_pipe[0]);
        if (in_pipe[1] >= 0) close(in_pipe[1]);
        if (out_pipe[0] >= 0) close(out_pipe[0]);
        if (out_pipe[1] >= 0) close(out_pipe[1]);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        mcp_set_err(err, err_len, "fork failed: %s", strerror(errno));
        close(in_pipe[0]);
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        /* Child */
        close(in_pipe[1]);
        close(out_pipe[0]);
        if (dup2(in_pipe[0], STDIN_FILENO) < 0) _exit(127);
        if (dup2(out_pipe[1], STDOUT_FILENO) < 0) _exit(127);
        /* Leave stderr shared so server logs are visible. */
        close(in_pipe[0]);
        close(out_pipe[1]);

        for (int i = 0; i < s->envc; i++) {
            if (s->env[i].key && s->env[i].value)
                setenv(s->env[i].key, s->env[i].value, 1);
        }

        /* argv: command + args */
        char **argv = mcp_xmalloc((size_t)(s->argc + 2) * sizeof(char *));
        argv[0] = s->command;
        for (int i = 0; i < s->argc; i++) argv[i + 1] = s->args[i];
        argv[s->argc + 1] = NULL;
        execvp(s->command, argv);
        fprintf(stderr, "ds4_mcp: failed to exec %s: %s\n",
                s->command, strerror(errno));
        _exit(127);
    }

    /* Parent */
    close(in_pipe[0]);
    close(out_pipe[1]);
    s->pid = pid;
    s->stdin_fd = in_pipe[1];
    s->stdout_fd = out_pipe[0];
    mcp_set_nonblock(s->stdout_fd, true);
    mcp_log(mcp, "spawned MCP server %s pid=%ld cmd=%s",
            s->name, (long)pid, s->command);
    return 0;
}

static int mcp_tool_add(ds4_mcp *mcp, const char *server_name,
                        const char *tool_name, const char *description,
                        const char *input_schema_json,
                        char *err, size_t err_len) {
    if (!tool_name || !tool_name[0]) return 0;
    if (mcp->tool_count >= DS4_MCP_MAX_TOOLS) {
        mcp_set_err(err, err_len, "too many MCP tools (max %d)", DS4_MCP_MAX_TOOLS);
        return -1;
    }
    if (!mcp->tools) {
        mcp->tools = mcp_xmalloc(DS4_MCP_MAX_TOOLS * sizeof(mcp_tool));
        memset(mcp->tools, 0, DS4_MCP_MAX_TOOLS * sizeof(mcp_tool));
    }
    char *exposed = ds4_mcp_exposed_name(server_name, tool_name);
    for (int i = 0; i < mcp->tool_count; i++) {
        if (!strcmp(mcp->tools[i].exposed_name, exposed)) {
            free(exposed);
            mcp_set_err(err, err_len, "duplicate MCP tool name: %s",
                        mcp->tools[i].exposed_name);
            return -1;
        }
    }
    mcp_tool *t = &mcp->tools[mcp->tool_count++];
    t->server_name = mcp_xstrdup(server_name);
    t->tool_name = mcp_xstrdup(tool_name);
    t->exposed_name = exposed;
    t->description = description ? mcp_xstrdup(description) : mcp_xstrdup("");
    t->input_schema_json = input_schema_json ? mcp_xstrdup(input_schema_json)
                                             : mcp_xstrdup("{\"type\":\"object\",\"properties\":{}}");
    return 0;
}

static int mcp_parse_tools_list_result(ds4_mcp *mcp, const char *server_name,
                                       const char *result_json,
                                       char *err, size_t err_len) {
    const char *tools_end = NULL;
    const char *tools = mcp_json_obj_get(result_json, "tools", &tools_end);
    if (!tools) {
        /* Some servers return the array directly as result. */
        const char *p = result_json;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == '[') {
            tools = p;
            tools_end = mcp_json_skip_value(p);
        }
    }
    if (!tools) {
        mcp_set_err(err, err_len, "tools/list missing tools array");
        return -1;
    }
    const char *p = tools;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '[') {
        mcp_set_err(err, err_len, "tools/list tools is not an array");
        return -1;
    }
    p++;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == ']') break;
        if (*p != '{') {
            mcp_set_err(err, err_len, "invalid tool entry");
            return -1;
        }
        const char *obj_end = mcp_json_skip_value(p);
        if (!obj_end) {
            mcp_set_err(err, err_len, "invalid tool entry");
            return -1;
        }
        char *obj = mcp_json_slice(p, obj_end);
        char *name = mcp_json_get_string(obj, "name");
        char *desc = mcp_json_get_string(obj, "description");
        const char *schema_end = NULL;
        const char *schema = mcp_json_obj_get(obj, "inputSchema", &schema_end);
        if (!schema) schema = mcp_json_obj_get(obj, "input_schema", &schema_end);
        char *schema_json = schema ? mcp_json_slice(schema, schema_end) : NULL;
        int rc = mcp_tool_add(mcp, server_name, name, desc, schema_json, err, err_len);
        free(name);
        free(desc);
        free(schema_json);
        free(obj);
        if (rc != 0) return -1;
        p = obj_end;
    }
    return 0;
}

static int mcp_server_initialize(ds4_mcp *mcp, mcp_server *s,
                                 char *err, size_t err_len) {
    const char *params =
        "{"
        "\"protocolVersion\":\"2024-11-05\","
        "\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"ds4-agent\",\"version\":\"1.0.0\"}"
        "}";
    char *resp = mcp_rpc(mcp, s, "initialize", params, err, err_len);
    if (!resp) return -1;
    char *result = mcp_json_get_result_raw(resp);
    free(resp);
    if (result) {
        const char *info_end = NULL;
        const char *info = mcp_json_obj_get(result, "serverInfo", &info_end);
        if (info) {
            char *info_obj = mcp_json_slice(info, info_end);
            free(s->server_title);
            s->server_title = mcp_json_get_string(info_obj, "name");
            free(info_obj);
        }
        free(result);
    }
    if (mcp_notify(mcp, s, "notifications/initialized", NULL, err, err_len) != 0)
        return -1;

    char *list_resp = mcp_rpc(mcp, s, "tools/list", "{}", err, err_len);
    if (!list_resp) return -1;
    char *list_result = mcp_json_get_result_raw(list_resp);
    free(list_resp);
    if (!list_result) {
        mcp_set_err(err, err_len, "tools/list returned no result");
        return -1;
    }
    int rc = mcp_parse_tools_list_result(mcp, s->name, list_result, err, err_len);
    free(list_result);
    if (rc != 0) return -1;
    s->connected = true;
    return 0;
}

/* ============================================================================
 * Tool call result extraction
 * ============================================================================
 */

static char *mcp_extract_call_text(const char *result_json) {
    /* Prefer content[].text text parts; fall back to whole result. */
    const char *content_end = NULL;
    const char *content = mcp_json_obj_get(result_json, "content", &content_end);
    if (!content) return mcp_xstrdup(result_json);

    const char *p = content;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '[') return mcp_json_slice(content, content_end);

    mcp_buf out = {0};
    p++;
    int parts = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == ']') break;
        if (*p != '{') break;
        const char *obj_end = mcp_json_skip_value(p);
        if (!obj_end) break;
        char *obj = mcp_json_slice(p, obj_end);
        char *type = mcp_json_get_string(obj, "type");
        char *text = mcp_json_get_string(obj, "text");
        if (text && (!type || !strcmp(type, "text"))) {
            if (parts++) mcp_buf_puts(&out, "\n");
            mcp_buf_puts(&out, text);
        } else {
            if (parts++) mcp_buf_puts(&out, "\n");
            mcp_buf_puts(&out, obj);
        }
        free(type);
        free(text);
        free(obj);
        p = obj_end;
    }
    if (out.len == 0) {
        free(out.ptr);
        return mcp_json_slice(content, content_end);
    }
    return mcp_buf_take(&out);
}

/* ============================================================================
 * Schema builders for the agent system prompt
 * ============================================================================
 */

static void mcp_schema_append_dsml_tool(mcp_buf *b, const mcp_tool *t) {
    mcp_buf_puts(b,
                 "{\n"
                 "  \"type\": \"function\",\n"
                 "  \"function\": {\n"
                 "    \"name\": \"");
    /* Names are restricted server__tool identifiers — no JSON escape needed. */
    mcp_buf_puts(b, t->exposed_name);
    mcp_buf_puts(b, "\",\n    \"description\": ");
    char *qdesc = mcp_json_quote(t->description && t->description[0] ?
                                 t->description : "MCP tool");
    mcp_buf_puts(b, qdesc);
    free(qdesc);
    mcp_buf_puts(b, ",\n    \"parameters\": ");
    mcp_buf_puts(b, t->input_schema_json && t->input_schema_json[0] ?
                    t->input_schema_json :
                    "{\"type\":\"object\",\"properties\":{}}");
    mcp_buf_puts(b, "\n  }\n}\n\n");
}

static void mcp_schema_append_glm_tool(mcp_buf *b, const mcp_tool *t) {
    mcp_buf_puts(b, "{\"type\":\"function\",\"function\":{\"name\":\"");
    mcp_buf_puts(b, t->exposed_name);
    mcp_buf_puts(b, "\",\"description\":");
    char *qdesc = mcp_json_quote(t->description && t->description[0] ?
                                 t->description : "MCP tool");
    mcp_buf_puts(b, qdesc);
    free(qdesc);
    mcp_buf_puts(b, ",\"parameters\":");
    mcp_buf_puts(b, t->input_schema_json && t->input_schema_json[0] ?
                    t->input_schema_json :
                    "{\"type\":\"object\",\"properties\":{}}");
    mcp_buf_puts(b, "}}\n");
}

char *ds4_mcp_build_dsml_schemas(const ds4_mcp *mcp) {
    if (!mcp || mcp->tool_count == 0) return mcp_xstrdup("");
    mcp_buf b = {0};
    mcp_buf_puts(&b,
                 "MCP tools are available with names of the form server__tool. "
                 "Call them like any other native tool.\n\n");
    for (int i = 0; i < mcp->tool_count; i++)
        mcp_schema_append_dsml_tool(&b, &mcp->tools[i]);
    return mcp_buf_take(&b);
}

char *ds4_mcp_build_glm_schemas(const ds4_mcp *mcp) {
    if (!mcp || mcp->tool_count == 0) return mcp_xstrdup("");
    mcp_buf b = {0};
    for (int i = 0; i < mcp->tool_count; i++)
        mcp_schema_append_glm_tool(&b, &mcp->tools[i]);
    return mcp_buf_take(&b);
}

/* ============================================================================
 * Public lifecycle
 * ============================================================================
 */

ds4_mcp *ds4_mcp_create(const ds4_mcp_config *cfg, char *err, size_t err_len) {
    if (!cfg || !cfg->config_path || !cfg->config_path[0]) {
        mcp_set_err(err, err_len, "MCP config path is required");
        return NULL;
    }
    FILE *fp = fopen(cfg->config_path, "rb");
    if (!fp) {
        mcp_set_err(err, err_len, "cannot open MCP config %s: %s",
                    cfg->config_path, strerror(errno));
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        mcp_set_err(err, err_len, "cannot seek MCP config");
        fclose(fp);
        return NULL;
    }
    long sz = ftell(fp);
    if (sz < 0 || sz > 4 * 1024 * 1024) {
        mcp_set_err(err, err_len, "MCP config is empty or too large");
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    char *text = mcp_xmalloc((size_t)sz + 1);
    if (fread(text, 1, (size_t)sz, fp) != (size_t)sz) {
        mcp_set_err(err, err_len, "failed to read MCP config");
        free(text);
        fclose(fp);
        return NULL;
    }
    text[sz] = '\0';
    fclose(fp);

    ds4_mcp *mcp = mcp_xmalloc(sizeof(*mcp));
    memset(mcp, 0, sizeof(*mcp));
    pthread_mutex_init(&mcp->mu, NULL);
    mcp->config_path = mcp_xstrdup(cfg->config_path);
    mcp->confirm = cfg->confirm;
    mcp->confirm_privdata = cfg->confirm_privdata;
    mcp->log = cfg->log;
    mcp->log_privdata = cfg->log_privdata;
    mcp->cancel = cfg->cancel;
    mcp->cancel_privdata = cfg->cancel_privdata;
    mcp->auto_approve = cfg->auto_approve;

    if (!ds4_mcp_parse_config_text(text, mcp, err, err_len)) {
        free(text);
        ds4_mcp_free(mcp);
        return NULL;
    }
    free(text);

    int enabled = 0;
    for (int i = 0; i < mcp->server_count; i++)
        if (!mcp->servers[i].disabled) enabled++;
    if (enabled == 0) {
        mcp_set_err(err, err_len, "MCP config has no enabled servers");
        ds4_mcp_free(mcp);
        return NULL;
    }
    return mcp;
}

void ds4_mcp_free(ds4_mcp *mcp) {
    if (!mcp) return;
    for (int i = 0; i < mcp->server_count; i++)
        mcp_server_clear(&mcp->servers[i]);
    free(mcp->servers);
    for (int i = 0; i < mcp->tool_count; i++)
        mcp_tool_clear(&mcp->tools[i]);
    free(mcp->tools);
    free(mcp->config_path);
    pthread_mutex_destroy(&mcp->mu);
    free(mcp);
}

int ds4_mcp_connect(ds4_mcp *mcp, char *err, size_t err_len) {
    if (!mcp) {
        mcp_set_err(err, err_len, "null MCP client");
        return -1;
    }
    if (mcp->connected) return 0;

    int enabled = 0;
    mcp_buf summary = {0};
    for (int i = 0; i < mcp->server_count; i++) {
        mcp_server *s = &mcp->servers[i];
        if (s->disabled) continue;
        if (enabled++) mcp_buf_puts(&summary, ", ");
        mcp_buf_puts(&summary, s->name);
        mcp_buf_puts(&summary, " (");
        mcp_buf_puts(&summary, s->command);
        for (int a = 0; a < s->argc; a++) {
            mcp_buf_puts(&summary, " ");
            mcp_buf_puts(&summary, s->args[a]);
        }
        mcp_buf_puts(&summary, ")");
    }
    char *summary_s = mcp_buf_take(&summary);

    if (!mcp->auto_approve) {
        if (!mcp->confirm) {
            free(summary_s);
            mcp_set_err(err, err_len,
                        "MCP connection requires interactive approval");
            return -1;
        }
        char prompt[512];
        snprintf(prompt, sizeof(prompt),
                 "Start MCP server%s %s? (y/n) ",
                 enabled == 1 ? "" : "s", summary_s);
        char cerr[160] = {0};
        int ok = mcp->confirm(mcp->confirm_privdata, prompt, cerr, sizeof(cerr));
        if (!ok) {
            mcp_set_err(err, err_len, "%s",
                        cerr[0] ? cerr : "user denied MCP server start");
            free(summary_s);
            return -1;
        }
    } else {
        mcp_log(mcp, "auto-approving MCP servers: %s", summary_s);
    }
    free(summary_s);

    int connected = 0;
    char last_err[256] = {0};
    for (int i = 0; i < mcp->server_count; i++) {
        mcp_server *s = &mcp->servers[i];
        if (s->disabled) continue;
        char serr[160] = {0};
        if (mcp_server_spawn(mcp, s, serr, sizeof(serr)) != 0) {
            snprintf(last_err, sizeof(last_err), "%s: %s", s->name, serr);
            mcp_log(mcp, "failed to spawn %s: %s", s->name, serr);
            continue;
        }
        if (mcp_server_initialize(mcp, s, serr, sizeof(serr)) != 0) {
            snprintf(last_err, sizeof(last_err), "%s: %s", s->name, serr);
            mcp_log(mcp, "failed to initialize %s: %s", s->name, serr);
            mcp_server_shutdown_runtime(s);
            s->disabled = true;
            continue;
        }
        connected++;
        mcp_log(mcp, "MCP server %s ready with tools", s->name);
    }

    if (connected == 0) {
        mcp_set_err(err, err_len, "no MCP servers connected%s%s",
                    last_err[0] ? ": " : "", last_err);
        return -1;
    }
    mcp->connected = true;
    return 0;
}

int ds4_mcp_server_count(const ds4_mcp *mcp) {
    return mcp ? mcp->server_count : 0;
}

int ds4_mcp_tool_count(const ds4_mcp *mcp) {
    return mcp ? mcp->tool_count : 0;
}

bool ds4_mcp_has_tool(const ds4_mcp *mcp, const char *exposed_name) {
    if (!mcp || !exposed_name) return false;
    for (int i = 0; i < mcp->tool_count; i++) {
        if (mcp->tools[i].exposed_name &&
            !strcmp(mcp->tools[i].exposed_name, exposed_name))
            return true;
    }
    return false;
}

char *ds4_mcp_call_tool(ds4_mcp *mcp, const char *exposed_name,
                        const char *args_json,
                        char *err, size_t err_len) {
    if (!mcp || !exposed_name) {
        mcp_set_err(err, err_len, "invalid MCP tool call");
        return NULL;
    }
    if (!mcp->connected) {
        if (ds4_mcp_connect(mcp, err, err_len) != 0) return NULL;
    }

    char server[128];
    char tool[256];
    if (!ds4_mcp_split_exposed_name(exposed_name, server, sizeof(server),
                                    tool, sizeof(tool)))
    {
        mcp_set_err(err, err_len, "invalid MCP tool name: %s", exposed_name);
        return NULL;
    }

    mcp_server *s = NULL;
    for (int i = 0; i < mcp->server_count; i++) {
        if (mcp->servers[i].name && !strcmp(mcp->servers[i].name, server) &&
            mcp->servers[i].connected)
        {
            s = &mcp->servers[i];
            break;
        }
    }
    if (!s) {
        mcp_set_err(err, err_len, "MCP server not connected: %s", server);
        return NULL;
    }

    bool known = false;
    for (int i = 0; i < mcp->tool_count; i++) {
        if (mcp->tools[i].exposed_name &&
            !strcmp(mcp->tools[i].exposed_name, exposed_name))
        {
            known = true;
            break;
        }
    }
    if (!known) {
        mcp_set_err(err, err_len, "unknown MCP tool: %s", exposed_name);
        return NULL;
    }

    char *qname = mcp_json_quote(tool);
    mcp_buf params = {0};
    mcp_buf_puts(&params, "{\"name\":");
    mcp_buf_puts(&params, qname);
    free(qname);
    mcp_buf_puts(&params, ",\"arguments\":");
    mcp_buf_puts(&params, args_json && args_json[0] ? args_json : "{}");
    mcp_buf_puts(&params, "}");
    char *params_s = mcp_buf_take(&params);

    pthread_mutex_lock(&mcp->mu);
    char *resp = mcp_rpc(mcp, s, "tools/call", params_s, err, err_len);
    pthread_mutex_unlock(&mcp->mu);
    free(params_s);
    if (!resp) return NULL;

    char *result = mcp_json_get_result_raw(resp);
    free(resp);
    if (!result) {
        mcp_set_err(err, err_len, "tools/call returned no result");
        return NULL;
    }

    /* isError flag */
    if (mcp_json_get_bool(result, "isError", false)) {
        char *text = mcp_extract_call_text(result);
        mcp_set_err(err, err_len, "%s", text && text[0] ? text : "MCP tool error");
        free(text);
        free(result);
        return NULL;
    }

    char *text = mcp_extract_call_text(result);
    free(result);
    return text;
}
