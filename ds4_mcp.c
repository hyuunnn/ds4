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
#define DS4_MCP_MAX_SERVER_NAME 64
#define DS4_MCP_MAX_TOOL_NAME 128
#define DS4_MCP_IO_TIMEOUT_MS 30000
#define DS4_MCP_MAX_MSG (16 * 1024 * 1024)
#define DS4_MCP_MAX_LIST_PAGES 64

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
        /* Track both braces and brackets so nested arrays inside objects (and
         * the reverse) cannot prematurely close the outer container. */
        const char *stack[64];
        int depth = 0;
        stack[depth++] = p;
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
            if (c == '"') {
                in_str = true;
                continue;
            }
            if (c == '{' || c == '[') {
                if (depth >= (int)(sizeof(stack) / sizeof(stack[0]))) return NULL;
                stack[depth++] = p - 1;
                continue;
            }
            if (c == '}' || c == ']') {
                char open = *stack[depth - 1];
                char expect = open == '{' ? '}' : ']';
                if (c != expect) return NULL;
                depth--;
            }
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
    /* Accept both numeric ids and the common string form "id":"1". */
    if (*v == '"') {
        char *s = mcp_json_parse_string_at(v, NULL);
        if (!s) return false;
        bool ok = atoi(s) == id;
        free(s);
        return ok;
    }
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
    int stderr_fd;
    int next_id;
    mcp_buf rx;
    bool connected;
    char *server_title; /* initialize result serverInfo.name if any */
    /* Owned KEY=VALUE strings kept until this server runtime is freed so the
     * post-fork child can still read them until exec replaces the address space. */
    char **child_env_owned;
    int child_env_owned_n;
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
    /* Sticky interactive deny: no later ensure_connected spawn until process exit. */
    bool spawn_denied;
    /* True after the user has approved (or auto-approved) at least once. */
    bool spawn_approved;
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

/* Stop a live process group and drop runtime I/O state, keeping config fields. */
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
    if (s->stderr_fd >= 0) {
        close(s->stderr_fd);
        s->stderr_fd = -1;
    }
    if (s->pid > 0) {
        /* Kill the process group so npx/node wrappers and their children die. */
        kill(-s->pid, SIGTERM);
        kill(s->pid, SIGTERM);
        int status = 0;
        for (int i = 0; i < 20; i++) {
            pid_t r = waitpid(s->pid, &status, WNOHANG);
            if (r == s->pid || (r < 0 && errno == ECHILD)) break;
            usleep(50 * 1000);
        }
        if (waitpid(s->pid, &status, WNOHANG) == 0) {
            kill(-s->pid, SIGKILL);
            kill(s->pid, SIGKILL);
            waitpid(s->pid, &status, 0);
        }
        s->pid = -1;
    }
    if (s->child_env_owned) {
        for (int i = 0; i < s->child_env_owned_n; i++) free(s->child_env_owned[i]);
        free(s->child_env_owned);
        s->child_env_owned = NULL;
        s->child_env_owned_n = 0;
    }
    s->connected = false;
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
    s->stderr_fd = -1;
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

/* Server keys must not contain "__" so exposed names server__tool split cleanly. */
static bool mcp_valid_server_name(const char *name) {
    if (!name || !name[0]) return false;
    size_t n = 0;
    for (const char *p = name; *p; p++, n++) {
        if (n >= DS4_MCP_MAX_SERVER_NAME) return false;
        if (!mcp_is_ident_char(*p)) return false;
        if (p[0] == '_' && p[1] == '_') return false;
    }
    return true;
}

/* Tool names: same charset, no "__", bounded length for call_tool split buffers. */
static bool mcp_valid_tool_name(const char *name) {
    if (!name || !name[0]) return false;
    size_t n = 0;
    for (const char *p = name; *p; p++, n++) {
        if (n >= DS4_MCP_MAX_TOOL_NAME) return false;
        if (!mcp_is_ident_char(*p)) return false;
        if (p[0] == '_' && p[1] == '_') return false;
    }
    return true;
}

/* True when s is a complete JSON value (number/bool/null/object/array). */
static bool mcp_looks_like_json_value(const char *s) {
    if (!s || !s[0]) return false;
    const char *end = mcp_json_skip_value(s);
    if (!end) return false;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') end++;
    return *end == '\0';
}

/* True when schema is a single JSON object we can splice into tool listings. */
static bool mcp_schema_is_safe_object(const char *schema) {
    if (!schema) return false;
    const char *p = schema;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '{') return false;
    return mcp_looks_like_json_value(p);
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
    bool closed = false;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == ']') {
            closed = true;
            break;
        }
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
    if (!closed) {
        for (int i = 0; i < n; i++) free(v[i]);
        free(v);
        mcp_set_err(err, err_len, "truncated JSON array (missing ']')");
        return -1;
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
    bool closed = false;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == '}') {
            closed = true;
            break;
        }
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
    if (!closed) {
        for (int i = 0; i < n; i++) {
            free(v[i].key);
            free(v[i].value);
        }
        free(v);
        mcp_set_err(err, err_len, "truncated JSON object (missing '}')");
        return -1;
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
    /* Reject truncated/malformed server objects early (e.g. unclosed args[]). */
    if (!mcp_json_skip_value(obj)) {
        mcp_set_err(err, err_len, "server %s: malformed JSON object", name);
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
    s->stderr_fd = -1;
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
    bool closed = false;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == '}') {
            closed = true;
            break;
        }
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
    if (!closed) {
        mcp_set_err(err, err_len, "truncated mcpServers object (missing '}')");
        return -1;
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
    /* First "__" is the delimiter; server names are forbidden from containing it. */
    const char *sep = strstr(exposed, "__");
    if (!sep || sep == exposed || !sep[2]) return false;
    /* Reject extra "__" in the tool side so split stays unambiguous. */
    if (strstr(sep + 2, "__")) return false;
    size_t sn = (size_t)(sep - exposed);
    if (sn + 1 > server_len) return false;
    memcpy(server, exposed, sn);
    server[sn] = '\0';
    if (strlen(sep + 2) + 1 > tool_len) return false;
    snprintf(tool, tool_len, "%s", sep + 2);
    if (!mcp_valid_server_name(server) || !mcp_valid_tool_name(tool))
        return false;
    return true;
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
        const char *v = values[i] ? values[i] : "";
        /*
         * Honor the parser's is_string flag:
         * - true  → always quote (DSML string="true", or GLM string args)
         * - false → emit raw only when the text is already a full JSON value;
         *           otherwise quote free text such as paths.
         * Callers that hardcode is_string=true for every arg (legacy GLM path)
         * should instead set the flag from value shape before calling this.
         */
        bool as_string = true;
        if (is_string && !is_string[i] &&
            v[0] && v[0] != '"' && mcp_looks_like_json_value(v))
            as_string = false;
        if (as_string) {
            char *qv = mcp_json_quote(v);
            mcp_buf_puts(&b, qv);
            free(qv);
        } else {
            mcp_buf_puts(&b, v[0] ? v : "null");
        }
    }
    mcp_buf_puts(&b, "}");
    return mcp_buf_take(&b);
}

/* ============================================================================
 * Transport: Content-Length framing + NDJSON fallback
 * ============================================================================
 */

typedef enum {
    MCP_RPC_OK = 0,
    MCP_RPC_APP_ERROR = 1,   /* JSON-RPC error object; process still healthy */
    MCP_RPC_TRANSPORT = -1,  /* pipe/timeout/interrupt; process may be dead */
} mcp_rpc_status;

static void mcp_ignore_sigpipe_once(void) {
    static int done = 0;
    if (done) return;
    signal(SIGPIPE, SIG_IGN);
    done = 1;
}

static int mcp_set_nonblock(int fd, bool on) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    int next = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(fd, F_SETFL, next);
}

static int mcp_set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int mcp_write_all(ds4_mcp *mcp, int fd, const char *buf, size_t n) {
    size_t off = 0;
    double deadline = (double)time(NULL) + (DS4_MCP_IO_TIMEOUT_MS / 1000.0) + 1.0;
    while (off < n) {
        if (mcp_cancel(mcp)) return -1;
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                double now = (double)time(NULL);
                if (now >= deadline) return -1;
                int wait_ms = (int)((deadline - now) * 1000.0);
                if (wait_ms < 50) wait_ms = 50;
                if (wait_ms > 1000) wait_ms = 1000;
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                if (poll(&pfd, 1, wait_ms) < 0) {
                    if (errno == EINTR) continue;
                    return -1;
                }
                continue;
            }
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int mcp_server_send(ds4_mcp *mcp, mcp_server *s, const char *json,
                           char *err, size_t err_len) {
    if (!s || s->stdin_fd < 0) {
        mcp_set_err(err, err_len, "MCP server not connected");
        return -1;
    }
    mcp_ignore_sigpipe_once();
    size_t n = strlen(json);
    /* Prefer Content-Length framing (MCP stdio standard). */
    char header[64];
    int hlen = snprintf(header, sizeof(header),
                        "Content-Length: %zu\r\n\r\n", n);
    if (hlen < 0 || (size_t)hlen >= sizeof(header)) {
        mcp_set_err(err, err_len, "MCP framing header failed");
        return -1;
    }
    if (mcp_write_all(mcp, s->stdin_fd, header, (size_t)hlen) != 0 ||
        mcp_write_all(mcp, s->stdin_fd, json, n) != 0)
    {
        mcp_set_err(err, err_len, "MCP write failed: %s",
                    errno ? strerror(errno) : "timeout, closed pipe, or interrupted");
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
    for (;;) {
        if (!s->rx.ptr || s->rx.len == 0) return NULL;

        /* Skip leading whitespace left after banners/partial drops. */
        size_t lead = 0;
        while (lead < s->rx.len &&
               (s->rx.ptr[lead] == ' ' || s->rx.ptr[lead] == '\t' ||
                s->rx.ptr[lead] == '\r' || s->rx.ptr[lead] == '\n'))
            lead++;
        if (lead) {
            memmove(s->rx.ptr, s->rx.ptr + lead, s->rx.len - lead);
            s->rx.len -= lead;
            s->rx.ptr[s->rx.len] = '\0';
            if (s->rx.len == 0) return NULL;
        }

        /* Content-Length framing only when the buffer starts with a header. */
        if (!strncmp(s->rx.ptr, "Content-Length:", 15) ||
            !strncmp(s->rx.ptr, "content-length:", 15))
        {
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
            if (content_len < 0 || content_len > DS4_MCP_MAX_MSG) {
                /* Bad header: drop one line and retry without recursion. */
                char *nl = memchr(s->rx.ptr, '\n', s->rx.len);
                if (!nl) return NULL;
                size_t drop = (size_t)(nl - s->rx.ptr) + 1;
                memmove(s->rx.ptr, s->rx.ptr + drop, s->rx.len - drop);
                s->rx.len -= drop;
                s->rx.ptr[s->rx.len] = '\0';
                continue;
            }
            size_t header_total = (size_t)(hdr_end - s->rx.ptr) + sep_len;
            if (s->rx.len < header_total + (size_t)content_len) return NULL;
            char *msg = mcp_xmalloc((size_t)content_len + 1);
            memcpy(msg, s->rx.ptr + header_total, (size_t)content_len);
            msg[content_len] = '\0';
            size_t remain = s->rx.len - header_total - (size_t)content_len;
            memmove(s->rx.ptr, s->rx.ptr + header_total + (size_t)content_len, remain);
            s->rx.len = remain;
            s->rx.ptr[s->rx.len] = '\0';
            return msg;
        }

        /* NDJSON: complete JSON value ending at a newline (not just first line). */
        char *nl = memchr(s->rx.ptr, '\n', s->rx.len);
        if (!nl) return NULL;
        /* Try successively longer prefixes ending at newlines until we have
         * one complete JSON value. */
        size_t try_end = 0;
        for (;;) {
            char *nln = memchr(s->rx.ptr + try_end, '\n', s->rx.len - try_end);
            if (!nln) return NULL;
            size_t line_end = (size_t)(nln - s->rx.ptr) + 1;
            size_t trim = line_end;
            if (trim > 0 && s->rx.ptr[trim - 1] == '\n') trim--;
            if (trim > 0 && s->rx.ptr[trim - 1] == '\r') trim--;
            if (trim == 0 || s->rx.ptr[0] != '{') {
                /* Banner / blank: drop through this newline and restart. */
                size_t remain = s->rx.len - line_end;
                memmove(s->rx.ptr, s->rx.ptr + line_end, remain);
                s->rx.len = remain;
                s->rx.ptr[s->rx.len] = '\0';
                break; /* outer for(;;) will re-examine buffer */
            }
            /* Temporarily NUL-terminate candidate and validate. */
            char saved = s->rx.ptr[trim];
            s->rx.ptr[trim] = '\0';
            const char *vend = mcp_json_skip_value(s->rx.ptr);
            bool complete = vend && *vend == '\0';
            s->rx.ptr[trim] = saved;
            if (complete) {
                char *msg = mcp_xmalloc(trim + 1);
                memcpy(msg, s->rx.ptr, trim);
                msg[trim] = '\0';
                size_t remain = s->rx.len - line_end;
                memmove(s->rx.ptr, s->rx.ptr + line_end, remain);
                s->rx.len = remain;
                s->rx.ptr[s->rx.len] = '\0';
                return msg;
            }
            try_end = line_end;
            if (try_end >= s->rx.len) return NULL;
        }
        continue;
    }
}

static void mcp_server_drain_stderr(ds4_mcp *mcp, mcp_server *s);

static char *mcp_server_recv_matching(ds4_mcp *mcp, mcp_server *s, int id,
                                      int timeout_ms, char *err, size_t err_len) {
    double deadline = (double)time(NULL) + (timeout_ms / 1000.0) + 1.0;
    for (;;) {
        if (mcp_cancel(mcp)) {
            mcp_set_err(err, err_len, "interrupted");
            return NULL;
        }
        mcp_server_drain_stderr(mcp, s);
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

        /* Poll stdout and stderr together so chatty servers cannot fill the
         * stderr pipe and deadlock while we wait for a reply. */
        struct pollfd pfds[2];
        int nfds = 0;
        int out_idx = -1, err_idx = -1;
        if (s->stdout_fd >= 0) {
            out_idx = nfds;
            pfds[nfds++] = (struct pollfd){ .fd = s->stdout_fd, .events = POLLIN };
        }
        if (s->stderr_fd >= 0) {
            err_idx = nfds;
            pfds[nfds++] = (struct pollfd){ .fd = s->stderr_fd, .events = POLLIN };
        }
        if (nfds == 0) {
            mcp_set_err(err, err_len, "MCP server stdout closed");
            return NULL;
        }
        int pr = poll(pfds, (nfds_t)nfds, wait_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            mcp_set_err(err, err_len, "MCP poll failed: %s", strerror(errno));
            return NULL;
        }
        if (err_idx >= 0 && (pfds[err_idx].revents & (POLLIN | POLLHUP)))
            mcp_server_drain_stderr(mcp, s);
        if (out_idx >= 0 && (pfds[out_idx].revents & (POLLIN | POLLHUP))) {
            if (mcp_server_read_more(s, 0, err, err_len) < 0) return NULL;
        }
    }
}

/*
 * Perform a JSON-RPC request.
 * - MCP_RPC_OK: *resp_out is the full response body (caller frees).
 * - MCP_RPC_APP_ERROR: server returned error; *resp_out may be NULL; err set;
 *   connection remains usable.
 * - MCP_RPC_TRANSPORT: I/O/timeout/cancel; *resp_out NULL; connection suspect.
 */
static mcp_rpc_status mcp_rpc(ds4_mcp *mcp, mcp_server *s, const char *method,
                              const char *params_json,
                              char **resp_out,
                              char *err, size_t err_len) {
    if (resp_out) *resp_out = NULL;
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
    if (mcp_server_send(mcp, s, wire, err, err_len) != 0) {
        free(wire);
        return MCP_RPC_TRANSPORT;
    }
    free(wire);
    char *resp = mcp_server_recv_matching(mcp, s, id, DS4_MCP_IO_TIMEOUT_MS,
                                          err, err_len);
    if (!resp) return MCP_RPC_TRANSPORT;
    if (mcp_json_has_error(resp)) {
        char *em = mcp_json_error_message(resp);
        mcp_set_err(err, err_len, "MCP %s error: %s", method,
                    em ? em : "unknown error");
        free(em);
        free(resp);
        return MCP_RPC_APP_ERROR;
    }
    if (resp_out) *resp_out = resp;
    else free(resp);
    return MCP_RPC_OK;
}

static int mcp_notify(ds4_mcp *mcp, mcp_server *s, const char *method,
                      const char *params_json, char *err, size_t err_len) {
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
    int rc = mcp_server_send(mcp, s, wire, err, err_len);
    free(wire);
    return rc;
}

static void mcp_server_drain_stderr(ds4_mcp *mcp, mcp_server *s);
static int mcp_server_spawn(ds4_mcp *mcp, mcp_server *s, char *err, size_t err_len);
static int mcp_server_initialize(ds4_mcp *mcp, mcp_server *s, char *err, size_t err_len);
static void mcp_remove_tools_for_server(ds4_mcp *mcp, const char *server_name);

/* ============================================================================
 * Spawn / initialize / tools.list
 * ============================================================================
 */

static int mcp_server_spawn(ds4_mcp *mcp, mcp_server *s, char *err, size_t err_len) {
    int in_pipe[2] = { -1, -1 };
    int out_pipe[2] = { -1, -1 };
    int err_pipe[2] = { -1, -1 };
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
        mcp_set_err(err, err_len, "pipe failed: %s", strerror(errno));
        if (in_pipe[0] >= 0) close(in_pipe[0]);
        if (in_pipe[1] >= 0) close(in_pipe[1]);
        if (out_pipe[0] >= 0) close(out_pipe[0]);
        if (out_pipe[1] >= 0) close(out_pipe[1]);
        if (err_pipe[0] >= 0) close(err_pipe[0]);
        if (err_pipe[1] >= 0) close(err_pipe[1]);
        return -1;
    }
    /* Parent keeps ends; child ends must not leak into bash/other forks. */
    mcp_set_cloexec(in_pipe[0]);
    mcp_set_cloexec(in_pipe[1]);
    mcp_set_cloexec(out_pipe[0]);
    mcp_set_cloexec(out_pipe[1]);
    mcp_set_cloexec(err_pipe[0]);
    mcp_set_cloexec(err_pipe[1]);

    /* Build argv in the parent so the child never mallocs after fork. */
    if (s->argc + 2 > DS4_MCP_MAX_ARGS + 2) {
        mcp_set_err(err, err_len, "too many args");
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return -1;
    }
    char *argv_stack[DS4_MCP_MAX_ARGS + 2];
    argv_stack[0] = s->command;
    for (int i = 0; i < s->argc; i++) argv_stack[i + 1] = s->args[i];
    argv_stack[s->argc + 1] = NULL;

    /*
     * Build a complete envp in the parent (no setenv after fork).  Start from
     * environ, then overlay server-specific KEY=VALUE entries.
     */
    extern char **environ;
    int base_envc = 0;
    if (environ) while (environ[base_envc]) base_envc++;
    int env_total = base_envc + s->envc + 1;
    char **envp = mcp_xmalloc((size_t)env_total * sizeof(char *));
    char **overlay = NULL;
    if (s->envc > 0) overlay = mcp_xmalloc((size_t)s->envc * sizeof(char *));
    for (int i = 0; i < s->envc; i++) {
        size_t kn = strlen(s->env[i].key ? s->env[i].key : "");
        size_t vn = strlen(s->env[i].value ? s->env[i].value : "");
        overlay[i] = mcp_xmalloc(kn + 1 + vn + 1);
        snprintf(overlay[i], kn + 1 + vn + 1, "%s=%s",
                 s->env[i].key ? s->env[i].key : "",
                 s->env[i].value ? s->env[i].value : "");
    }
    int out_i = 0;
    for (int i = 0; i < base_envc; i++) {
        const char *e = environ[i];
        const char *eq = strchr(e, '=');
        size_t klen = eq ? (size_t)(eq - e) : strlen(e);
        bool replaced = false;
        for (int j = 0; j < s->envc; j++) {
            const char *k = s->env[j].key ? s->env[j].key : "";
            if (strlen(k) == klen && !strncmp(e, k, klen)) {
                envp[out_i++] = overlay[j];
                replaced = true;
                break;
            }
        }
        if (!replaced) envp[out_i++] = (char *)e;
    }
    for (int j = 0; j < s->envc; j++) {
        bool used = false;
        for (int i = 0; i < out_i; i++) {
            if (envp[i] == overlay[j]) { used = true; break; }
        }
        if (!used) envp[out_i++] = overlay[j];
    }
    envp[out_i] = NULL;

    pid_t pid = fork();
    if (pid < 0) {
        mcp_set_err(err, err_len, "fork failed: %s", strerror(errno));
        for (int i = 0; i < s->envc; i++) free(overlay[i]);
        free(overlay);
        free(envp);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        /* Child: only async-signal-safe calls until exec. */
        setpgid(0, 0);
        if (dup2(in_pipe[0], STDIN_FILENO) < 0) _exit(127);
        if (dup2(out_pipe[1], STDOUT_FILENO) < 0) _exit(127);
        if (dup2(err_pipe[1], STDERR_FILENO) < 0) _exit(127);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);

        int maxfd = (int)sysconf(_SC_OPEN_MAX);
        if (maxfd < 0) maxfd = 1024;
        if (maxfd > 65536) maxfd = 65536;
        for (int fd = 3; fd < maxfd; fd++)
            close(fd);

        /* Prefer absolute/path command via execve(envp). For PATH lookup without
         * touching malloc, hand envp to execvpe when available. */
#if defined(__linux__) || defined(__GLIBC__)
        execvpe(s->command, argv_stack, envp);
#else
        execve(s->command, argv_stack, envp);
        if (!strchr(s->command, '/')) {
            /* Last resort PATH search; environ still points at parent copy —
             * only safe if parent has not freed envp yet. Parent waits via
             * short yield before free (below). */
            environ = envp;
            execvp(s->command, argv_stack);
        }
#endif
        const char *msg = "ds4_mcp: exec failed\n";
        (void)write(STDERR_FILENO, msg, 22);
        _exit(127);
    }

    /* Parent: do not free child-visible env strings until this server is shut
     * down. Stash owned KEY=VALUE overlays on the server object. */
    setpgid(pid, pid);
    if (s->child_env_owned) {
        for (int i = 0; i < s->child_env_owned_n; i++) free(s->child_env_owned[i]);
        free(s->child_env_owned);
    }
    s->child_env_owned = overlay;
    s->child_env_owned_n = s->envc;
    free(envp); /* pointers only; owned strings are in child_env_owned / environ */
    close(in_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[1]);

    s->stderr_fd = err_pipe[0];
    s->pid = pid;
    s->stdin_fd = in_pipe[1];
    s->stdout_fd = out_pipe[0];
    mcp_set_nonblock(s->stdout_fd, true);
    mcp_set_nonblock(s->stdin_fd, true);
    mcp_set_nonblock(s->stderr_fd, true);
    mcp_set_cloexec(s->stdin_fd);
    mcp_set_cloexec(s->stdout_fd);
    mcp_set_cloexec(s->stderr_fd);
    mcp_server_drain_stderr(mcp, s);
    mcp_log(mcp, "spawned MCP server %s pid=%ld cmd=%s",
            s->name, (long)pid, s->command);
    return 0;
}

static void mcp_remove_tools_for_server(ds4_mcp *mcp, const char *server_name) {
    if (!mcp || !server_name || !mcp->tools) return;
    int w = 0;
    for (int i = 0; i < mcp->tool_count; i++) {
        if (mcp->tools[i].server_name &&
            !strcmp(mcp->tools[i].server_name, server_name))
        {
            mcp_tool_clear(&mcp->tools[i]);
            continue;
        }
        if (w != i) mcp->tools[w] = mcp->tools[i];
        w++;
    }
    /* Zero vacated slots so a later free cannot double-free moved entries. */
    for (int i = w; i < mcp->tool_count; i++)
        memset(&mcp->tools[i], 0, sizeof(mcp->tools[i]));
    mcp->tool_count = w;
}

static void mcp_server_drain_stderr(ds4_mcp *mcp, mcp_server *s) {
    if (!s || s->stderr_fd < 0) return;
    char buf[1024];
    for (;;) {
        ssize_t n = read(s->stderr_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            for (ssize_t i = 0; i < n; i++)
                if (buf[i] == '\n' || buf[i] == '\r') buf[i] = ' ';
            mcp_log(mcp, "mcp %s stderr: %s", s->name ? s->name : "?", buf);
            continue;
        }
        break;
    }
}

static int mcp_tool_add(ds4_mcp *mcp, const char *server_name,
                        const char *tool_name, const char *description,
                        const char *input_schema_json,
                        char *err, size_t err_len) {
    if (!tool_name || !tool_name[0]) return 0;
    if (!mcp_valid_tool_name(tool_name)) {
        mcp_set_err(err, err_len,
                    "invalid MCP tool name from %s: %s "
                    "(use [A-Za-z0-9_.-], no \"__\", max %d chars)",
                    server_name ? server_name : "?", tool_name,
                    DS4_MCP_MAX_TOOL_NAME);
        return -1;
    }
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
    if (input_schema_json && mcp_schema_is_safe_object(input_schema_json)) {
        t->input_schema_json = mcp_xstrdup(input_schema_json);
    } else {
        if (input_schema_json && input_schema_json[0])
            mcp_log(mcp, "mcp %s: dropping unsafe inputSchema for tool %s",
                    server_name ? server_name : "?", tool_name);
        t->input_schema_json =
            mcp_xstrdup("{\"type\":\"object\",\"properties\":{}}");
    }
    return 0;
}

static int mcp_parse_tools_array(ds4_mcp *mcp, const char *server_name,
                                 const char *tools, char *err, size_t err_len) {
    const char *p = tools;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '[') {
        mcp_set_err(err, err_len, "tools/list tools is not an array");
        return -1;
    }
    p++;
    bool closed = false;
    int skipped = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (*p == ']') {
            closed = true;
            break;
        }
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
        char add_err[192] = {0};
        int rc = mcp_tool_add(mcp, server_name, name, desc, schema_json,
                              add_err, sizeof(add_err));
        if (rc != 0) {
            /* Soft-skip only invalid names / bad schema tools. Hard limits and
             * duplicates abort listing so the operator sees a real error. */
            bool hard = strstr(add_err, "too many MCP tools") != NULL ||
                        strstr(add_err, "duplicate MCP tool") != NULL;
            if (hard) {
                free(name);
                free(desc);
                free(schema_json);
                free(obj);
                mcp_set_err(err, err_len, "%s", add_err);
                return -1;
            }
            mcp_log(mcp, "mcp %s: skipping tool: %s",
                    server_name ? server_name : "?",
                    add_err[0] ? add_err : "invalid tool");
            skipped++;
        }
        free(name);
        free(desc);
        free(schema_json);
        free(obj);
        p = obj_end;
    }
    if (!closed) {
        mcp_set_err(err, err_len, "truncated tools array (missing ']')");
        return -1;
    }
    if (skipped)
        mcp_log(mcp, "mcp %s: skipped %d invalid tool(s)",
                server_name ? server_name : "?", skipped);
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
    return mcp_parse_tools_array(mcp, server_name, tools, err, err_len);
}

/* Fetch all tools/list pages when the server returns nextCursor. */
static int mcp_server_list_all_tools(ds4_mcp *mcp, mcp_server *s,
                                    char *err, size_t err_len) {
    char *cursor = NULL;
    for (int page = 0; page < DS4_MCP_MAX_LIST_PAGES; page++) {
        mcp_server_drain_stderr(mcp, s);
        mcp_buf params = {0};
        if (cursor && cursor[0]) {
            char *qc = mcp_json_quote(cursor);
            mcp_buf_puts(&params, "{\"cursor\":");
            mcp_buf_puts(&params, qc);
            mcp_buf_puts(&params, "}");
            free(qc);
        } else {
            mcp_buf_puts(&params, "{}");
        }
        char *params_s = mcp_buf_take(&params);
        char *list_resp = NULL;
        mcp_rpc_status st = mcp_rpc(mcp, s, "tools/list", params_s,
                                    &list_resp, err, err_len);
        free(params_s);
        if (st != MCP_RPC_OK) {
            free(cursor);
            free(list_resp);
            return -1;
        }
        char *list_result = mcp_json_get_result_raw(list_resp);
        free(list_resp);
        if (!list_result) {
            free(cursor);
            mcp_set_err(err, err_len, "tools/list returned no result");
            return -1;
        }
        int rc = mcp_parse_tools_list_result(mcp, s->name, list_result, err, err_len);
        if (rc != 0) {
            free(list_result);
            free(cursor);
            return -1;
        }
        free(cursor);
        cursor = mcp_json_get_string(list_result, "nextCursor");
        free(list_result);
        if (!cursor || !cursor[0]) {
            free(cursor);
            cursor = NULL;
            return 0;
        }
    }
    free(cursor);
    mcp_set_err(err, err_len,
                "tools/list exceeded %d pages (still has nextCursor)",
                DS4_MCP_MAX_LIST_PAGES);
    return -1;
}

static int mcp_server_initialize(ds4_mcp *mcp, mcp_server *s,
                                 char *err, size_t err_len) {
    int tools_before = mcp->tool_count;
    const char *params =
        "{"
        "\"protocolVersion\":\"2024-11-05\","
        "\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"ds4-agent\",\"version\":\"1.0.0\"}"
        "}";
    char *resp = NULL;
    if (mcp_rpc(mcp, s, "initialize", params, &resp, err, err_len) != MCP_RPC_OK)
        return -1;
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
    if (mcp_notify(mcp, s, "notifications/initialized", NULL, err, err_len) != 0) {
        mcp_remove_tools_for_server(mcp, s->name);
        return -1;
    }

    if (mcp_server_list_all_tools(mcp, s, err, err_len) != 0) {
        /* Drop any tools partially registered for this server. */
        if (mcp->tool_count > tools_before)
            mcp_remove_tools_for_server(mcp, s->name);
        return -1;
    }
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
                 "    \"name\": ");
    /* Validate-then-quote: names are restricted, but still JSON-escape. */
    char *qname = mcp_json_quote(t->exposed_name ? t->exposed_name : "");
    mcp_buf_puts(b, qname);
    free(qname);
    mcp_buf_puts(b, ",\n    \"description\": ");
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
    mcp_buf_puts(b, "{\"type\":\"function\",\"function\":{\"name\":");
    char *qname = mcp_json_quote(t->exposed_name ? t->exposed_name : "");
    mcp_buf_puts(b, qname);
    free(qname);
    mcp_buf_puts(b, ",\"description\":");
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

    int need = 0;
    for (int i = 0; i < mcp->server_count; i++) {
        mcp_server *s = &mcp->servers[i];
        if (!s->disabled && !s->connected) need++;
    }
    if (need == 0) {
        /* All enabled servers already live. */
        if (ds4_mcp_connected_server_count(mcp) > 0) {
            mcp->connected = true;
            return 0;
        }
        mcp_set_err(err, err_len, "no enabled MCP servers in config");
        return -1;
    }

    int enabled = 0;
    mcp_buf summary = {0};
    for (int i = 0; i < mcp->server_count; i++) {
        mcp_server *s = &mcp->servers[i];
        if (s->disabled || s->connected) continue;
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

    if (!mcp->auto_approve && !mcp->spawn_approved) {
        /* Interactive approval is sticky for the whole client lifetime. */
        if (mcp->spawn_denied) {
            free(summary_s);
            mcp_set_err(err, err_len, "MCP server start was denied");
            return -1;
        }
        if (!mcp->confirm) {
            free(summary_s);
            mcp_set_err(err, err_len,
                        "MCP connection requires interactive approval");
            return -1;
        }
        char prompt[768];
        snprintf(prompt, sizeof(prompt),
                 "Start MCP server%s %s? (y/n) ",
                 enabled == 1 ? "" : "s", summary_s);
        char cerr[160] = {0};
        int ok = mcp->confirm(mcp->confirm_privdata, prompt, cerr, sizeof(cerr));
        if (!ok) {
            mcp->spawn_denied = true;
            mcp_set_err(err, err_len, "%s",
                        cerr[0] ? cerr : "user denied MCP server start");
            free(summary_s);
            return -1;
        }
        mcp->spawn_approved = true;
    } else if (mcp->auto_approve && !mcp->spawn_approved) {
        mcp->spawn_approved = true;
        mcp_log(mcp, "auto-approving MCP servers: %s", summary_s);
    } else {
        mcp_log(mcp, "retrying MCP servers: %s", summary_s);
    }
    free(summary_s);

    int connected_now = 0;
    char last_err[256] = {0};
    for (int i = 0; i < mcp->server_count; i++) {
        mcp_server *s = &mcp->servers[i];
        if (s->disabled || s->connected) continue;
        char serr[160] = {0};
        if (mcp_server_spawn(mcp, s, serr, sizeof(serr)) != 0) {
            snprintf(last_err, sizeof(last_err), "%s: %s", s->name, serr);
            mcp_log(mcp, "failed to spawn %s: %s", s->name, serr);
            continue;
        }
        if (mcp_server_initialize(mcp, s, serr, sizeof(serr)) != 0) {
            snprintf(last_err, sizeof(last_err), "%s: %s", s->name, serr);
            mcp_log(mcp, "failed to initialize %s: %s", s->name, serr);
            mcp_remove_tools_for_server(mcp, s->name);
            mcp_server_shutdown_runtime(s);
            continue;
        }
        connected_now++;
        mcp_log(mcp, "MCP server %s ready with tools", s->name);
    }

    int total = ds4_mcp_connected_server_count(mcp);
    if (total == 0) {
        mcp->connected = false;
        mcp_set_err(err, err_len, "no MCP servers connected%s%s",
                    last_err[0] ? ": " : "", last_err);
        return -1;
    }
    mcp->connected = true;
    if (connected_now == 0 && need > 0) {
        /* Already had some servers; retry wave added none. Not fatal. */
        mcp_log(mcp, "MCP retry did not recover any additional servers");
    }
    return 0;
}

int ds4_mcp_server_count(const ds4_mcp *mcp) {
    return mcp ? mcp->server_count : 0;
}

int ds4_mcp_connected_server_count(const ds4_mcp *mcp) {
    if (!mcp) return 0;
    int n = 0;
    for (int i = 0; i < mcp->server_count; i++)
        if (mcp->servers[i].connected) n++;
    return n;
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

bool ds4_mcp_is_configured_tool(const ds4_mcp *mcp, const char *exposed_name) {
    if (!mcp || !exposed_name) return false;
    char server[DS4_MCP_MAX_SERVER_NAME + 1];
    char tool[DS4_MCP_MAX_TOOL_NAME + 1];
    if (!ds4_mcp_split_exposed_name(exposed_name, server, sizeof(server),
                                    tool, sizeof(tool)))
        return false;
    for (int i = 0; i < mcp->server_count; i++) {
        if (mcp->servers[i].name && !mcp->servers[i].disabled &&
            !strcmp(mcp->servers[i].name, server))
            return true;
    }
    return false;
}

/* Mark a live server dead if its process has exited. Use the shared shutdown
 * path so title/next_id/env ownership stay consistent. */
static void mcp_server_refresh_liveness(mcp_server *s) {
    if (!s || !s->connected || s->pid <= 0) return;
    int status = 0;
    pid_t r = waitpid(s->pid, &status, WNOHANG);
    if (r == s->pid || (r < 0 && errno == ECHILD)) {
        s->pid = -1; /* prevent double-kill in shutdown */
        mcp_server_shutdown_runtime(s);
    }
}

/* Spawn + initialize one server only (used for on-demand reconnect). */
static int mcp_server_ensure_connected(ds4_mcp *mcp, mcp_server *s,
                                       char *err, size_t err_len) {
    if (!s || s->disabled) {
        mcp_set_err(err, err_len, "MCP server disabled");
        return -1;
    }
    if (mcp->spawn_denied) {
        mcp_set_err(err, err_len, "MCP server start was denied");
        return -1;
    }
    /* Never spawn without an explicit prior approval (or auto_approve). */
    if (!mcp->spawn_approved && !mcp->auto_approve) {
        mcp_set_err(err, err_len, "MCP servers have not been approved");
        return -1;
    }
    mcp_server_refresh_liveness(s);
    if (s->connected) return 0;

    if (s->pid > 0 || s->stdin_fd >= 0 || s->stdout_fd >= 0)
        mcp_server_shutdown_runtime(s);

    char serr[160] = {0};
    if (mcp_server_spawn(mcp, s, serr, sizeof(serr)) != 0) {
        mcp_set_err(err, err_len, "%s", serr);
        return -1;
    }
    mcp_remove_tools_for_server(mcp, s->name);
    if (mcp_server_initialize(mcp, s, serr, sizeof(serr)) != 0) {
        mcp_remove_tools_for_server(mcp, s->name);
        mcp_server_shutdown_runtime(s);
        mcp_set_err(err, err_len, "%s", serr);
        return -1;
    }
    mcp->connected = true;
    return 0;
}

char *ds4_mcp_call_tool(ds4_mcp *mcp, const char *exposed_name,
                        const char *args_json,
                        char *err, size_t err_len) {
    if (!mcp || !exposed_name) {
        mcp_set_err(err, err_len, "invalid MCP tool call");
        return NULL;
    }

    char server[DS4_MCP_MAX_SERVER_NAME + 1];
    char tool[DS4_MCP_MAX_TOOL_NAME + 1];
    if (!ds4_mcp_split_exposed_name(exposed_name, server, sizeof(server),
                                    tool, sizeof(tool)))
    {
        mcp_set_err(err, err_len, "invalid MCP tool name: %s", exposed_name);
        return NULL;
    }

    mcp_server *s = NULL;
    for (int i = 0; i < mcp->server_count; i++) {
        if (mcp->servers[i].name && !strcmp(mcp->servers[i].name, server)) {
            s = &mcp->servers[i];
            break;
        }
    }
    if (!s || s->disabled) {
        mcp_set_err(err, err_len, "unknown MCP server: %s", server);
        return NULL;
    }

    /* Ensure this server is live (and only this server). */
    {
        char cerr[192] = {0};
        if (mcp_server_ensure_connected(mcp, s, cerr, sizeof(cerr)) != 0) {
            mcp_set_err(err, err_len, "MCP server not connected: %s (%s)",
                        server, cerr[0] ? cerr : "connect failed");
            return NULL;
        }
    }
    mcp_server_drain_stderr(mcp, s);

    /* After reconnect, tools were re-listed. If the specific tool is still
     * missing, report that without tearing down the server. */
    if (!ds4_mcp_has_tool(mcp, exposed_name)) {
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

    char *resp = NULL;
    pthread_mutex_lock(&mcp->mu);
    mcp_rpc_status st = mcp_rpc(mcp, s, "tools/call", params_s, &resp, err, err_len);
    pthread_mutex_unlock(&mcp->mu);
    free(params_s);

    if (st == MCP_RPC_TRANSPORT) {
        /* Keep tool catalog. Only drop the live process so a later approved
         * call can respawn. Do not treat cancel the same as death if no bytes
         * of a new frame were committed — still shut down to avoid partial
         * frame desync on reuse. */
        mcp_server_shutdown_runtime(s);
        if (ds4_mcp_connected_server_count(mcp) == 0)
            mcp->connected = false;
        if (!err[0])
            mcp_set_err(err, err_len, "MCP transport error calling %s", exposed_name);
        return NULL;
    }
    if (st == MCP_RPC_APP_ERROR) {
        /* Protocol/application error: process stays up, tools stay registered. */
        return NULL;
    }

    char *result = mcp_json_get_result_raw(resp);
    free(resp);
    if (!result) {
        mcp_set_err(err, err_len, "tools/call returned no result");
        return NULL;
    }

    /* isError flag is a normal tool-level failure, not transport death. */
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
