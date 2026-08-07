#ifndef DS4_MCP_H
#define DS4_MCP_H

#include <stddef.h>
#include <stdbool.h>

/*
 * Minimal MCP client for ds4-agent.
 *
 * Scope: stdio transport, tools/list + tools/call only.  Servers are launched
 * from a Claude/Cursor-style JSON config and exposed to the model as
 * server__toolname native tools.
 */

typedef int (*ds4_mcp_confirm_fn)(void *privdata, const char *message,
                                  char *err, size_t err_len);
typedef void (*ds4_mcp_log_fn)(void *privdata, const char *message);
typedef bool (*ds4_mcp_cancel_fn)(void *privdata);

typedef struct {
    const char *config_path;
    ds4_mcp_confirm_fn confirm;
    void *confirm_privdata;
    ds4_mcp_log_fn log;
    void *log_privdata;
    ds4_mcp_cancel_fn cancel;
    void *cancel_privdata;
    /* When true, skip the interactive connect prompt (non-interactive mode). */
    bool auto_approve;
} ds4_mcp_config;

typedef struct ds4_mcp ds4_mcp;

/* Parse config and leave servers unstarted until ds4_mcp_connect(). */
ds4_mcp *ds4_mcp_create(const ds4_mcp_config *cfg, char *err, size_t err_len);
void ds4_mcp_free(ds4_mcp *mcp);

/* Spawn enabled servers, initialize, and list tools.  May prompt via confirm. */
int ds4_mcp_connect(ds4_mcp *mcp, char *err, size_t err_len);

/* Configured servers, currently connected servers, and discovered tools. */
int ds4_mcp_server_count(const ds4_mcp *mcp);
int ds4_mcp_connected_server_count(const ds4_mcp *mcp);
int ds4_mcp_tool_count(const ds4_mcp *mcp);

/* Build DSML or GLM schema text for discovered tools.  Caller frees. */
char *ds4_mcp_build_dsml_schemas(const ds4_mcp *mcp);
char *ds4_mcp_build_glm_schemas(const ds4_mcp *mcp);

/* Look up a model-visible name of the form "server__tool". */
bool ds4_mcp_has_tool(const ds4_mcp *mcp, const char *exposed_name);

/*
 * Call an exposed tool.  args_json is a JSON object string for arguments
 * (e.g. {"path":"/tmp/a.apk"}).  On success returns malloc'd text content
 * (or a compact JSON dump of non-text content).  On failure returns NULL
 * and fills err.
 */
char *ds4_mcp_call_tool(ds4_mcp *mcp, const char *exposed_name,
                        const char *args_json,
                        char *err, size_t err_len);

/* Pure helpers used by tests and by the agent tool dispatcher. */
char *ds4_mcp_exposed_name(const char *server, const char *tool);
bool ds4_mcp_split_exposed_name(const char *exposed, char *server, size_t server_len,
                                char *tool, size_t tool_len);

/* Build a JSON object from name/value pairs.  is_string[i] controls quoting. */
char *ds4_mcp_build_args_json(const char *const *names,
                              const char *const *values,
                              const bool *is_string,
                              int n);

/* Unit-test hooks for config parsing without spawning. */
bool ds4_mcp_parse_config_text(const char *json, ds4_mcp *mcp,
                               char *err, size_t err_len);

#endif
