/*
**  mod_mongo.cpp -- Apache mongo module
**
**  Then activate it in Apache's httpd.conf file:
**
**    # httpd.conf
**    LoadModule mongo_module modules/mod_mongo.so
**    <IfModule mongo_module>
**      MongoHost    localhost
**      MongoPort    27017
**      MongoTimeout 5
**    </IfModule>
**    AddHandler mongo-script .mongo
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

/* v8.hpp */
#include "v8.hpp"

/* httpd */
#ifdef __cplusplus
extern "C" {
#endif
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apreq2/apreq_module_apache2.h"
#ifdef __cplusplus
}
#endif

/* log */
#ifdef AP_MONGO_DEBUG_LOG_LEVEL
#define MONGO_DEBUG_LOG_LEVEL AP_MONGO_DEBUG_LOG_LEVEL
#else
#define MONGO_DEBUG_LOG_LEVEL APLOG_DEBUG
#endif

#define _RERR(r, format, args...)                                       \
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0,                            \
                  r, "[MONGO] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _SERR(s, format, args...)                                       \
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0,                             \
                 s, "[MONGO] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _PERR(p, format, args...)                                       \
    ap_log_perror(APLOG_MARK, APLOG_CRIT, 0,                            \
                  p, "[MONGO] %s(%d): "format, __FILE__, __LINE__, ##args)

#define _RDEBUG(r, format, args...)                                     \
    ap_log_rerror(APLOG_MARK, MONGO_DEBUG_LOG_LEVEL, 0,                 \
                  r, "[MONGO_DEBUG] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _SDEBUG(s, format, args...)                                     \
    ap_log_error(APLOG_MARK, MONGO_DEBUG_LOG_LEVEL, 0,                  \
                 s, "[MONGO_DEBUG] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _PDEBUG(p, format, args...)                                     \
    ap_log_perror(APLOG_MARK, MONGO_DEBUG_LOG_LEVEL, 0,                 \
                  p, "[MONGO_DEBUG] %s(%d): "format, __FILE__, __LINE__, ##args)

/* default parameter */
#define MONGO_DEFAULT_HOST         "localhost"
#define MONGO_DEFAULT_PORT         27017
#define MONGO_DEFAULT_TIMEOUT      0
#define MONGO_DEFAULT_CONTENT_TYPE "application/json; charset=utf-8";
#define MONGO_CONFIG_UNSET         -1

/* mongo server config */
typedef struct {
    apr_pool_t *pool;
    char *host;
    int port;
    int timeout;
    mongo::DBClientConnection *cli;
    V8::js *js;
#ifdef AP_USE_V8_ISOLATE
    v8::Isolate *isolate;
#endif
} mongo_server_config_t;

/* Functions */
static const char *mongo_set_host(cmd_parms *parms, void *conf, char *arg);
static const char *mongo_set_port(cmd_parms *parms, void *conf, char *arg);
static const char *mongo_set_timeout(cmd_parms *parms, void *conf, char *arg);

static void *mongo_create_server_config(apr_pool_t *p, server_rec *s);
static void *mongo_merge_server_config(apr_pool_t *p,
                                       void *base_server, void *override_server);
static int mongo_post_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s);
static void mongo_child_init(apr_pool_t *p, server_rec *s);
static int mongo_handler(request_rec* r);

/* Commands */
static const command_rec mongo_cmds[] =
{
    AP_INIT_TAKE1(
        "MongoHost", (const char*(*)())(mongo_set_host), NULL, RSRC_CONF,
        "mongoDB host."),
    AP_INIT_TAKE1(
        "MongoPort", (const char*(*)())(mongo_set_port), NULL, RSRC_CONF,
        "mongoDB port."),
    AP_INIT_TAKE1(
        "MongoTimeout", (const char*(*)())(mongo_set_timeout), NULL, RSRC_CONF,
        "mongoDB read/write timeout (not connection)."),
    { NULL, NULL, NULL, 0, TAKE1, NULL }
};

/* Hooks */
static void mongo_register_hooks(apr_pool_t *p)
{
    /* ap_hook_post_config(mongo_post_config, NULL, NULL, APR_HOOK_MIDDLE); */
    ap_hook_child_init(mongo_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(mongo_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Module */
#ifdef __cplusplus
extern "C" {
#endif
module AP_MODULE_DECLARE_DATA mongo_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir    config structures */
    NULL,                       /* merge  per-dir    config structures */
    mongo_create_server_config, /* create per-server config structures */
    mongo_merge_server_config,  /* merge  per-server config structures */
    mongo_cmds,                 /* table of config file commands       */
    mongo_register_hooks        /* register hooks                      */
};
#ifdef __cplusplus
}
#endif

/* config settings */
static const char *mongo_set_host(cmd_parms *parms, void *conf, char *arg)
{
    mongo_server_config_t *config;

    if (strlen(arg) == 0) {
        return "MongoHost argument must be a string representing a host.";
    }

    config = (mongo_server_config_t *)ap_get_module_config(
        parms->server->module_config, &mongo_module);

    config->host = apr_pstrdup(parms->pool, arg);

    return NULL;
}

static const char *mongo_set_port(cmd_parms *parms, void *conf, char *arg)
{
    mongo_server_config_t *config;
    int port;

    if (sscanf(arg, "%d", &port) != 1 || port < 0) {
        return "MongoPort must be an integer representing the port number";
    }

    config =(mongo_server_config_t *)ap_get_module_config(
        parms->server->module_config, &mongo_module);

    config->port = port;

    return NULL;
}

static const char *mongo_set_timeout(cmd_parms *parms, void *conf, char *arg)
{
    mongo_server_config_t *config;
    int timeout;

    if (sscanf(arg, "%d", &timeout) != 1 || timeout < 0) {
        return "MongoTimeout must be an integer representing the timeout number";
    }

    config =(mongo_server_config_t *)ap_get_module_config(
        parms->server->module_config, &mongo_module);

    config->timeout = timeout;

    return NULL;
}

/* read file */
static apr_status_t mongo_read_file(const char *path, const char **out,
                                 apr_size_t *outlen, apr_pool_t *p,
                                 apr_pool_t *ptemp)
{
    char *c;
    apr_size_t len = 0;
    apr_status_t rv;
    apr_file_t *fp;
    apr_finfo_t fi;

    *out = NULL;
    *outlen = 0;

    rv = apr_file_open(&fp, path, APR_READ|APR_BINARY|APR_BUFFERED,
                       APR_OS_DEFAULT, ptemp);
    if (rv != APR_SUCCESS) {
        _PERR(p, "file open: %s", path);
        return rv;
    }

    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, fp);
    if (rv != APR_SUCCESS) {
        _PERR(p, "file info get: %s", path);
        return rv;
    }

    apr_bucket_alloc_t *ba = apr_bucket_alloc_create(ptemp);
    apr_bucket_brigade *bb = apr_brigade_create(ptemp, ba);

    apr_brigade_insert_file(bb, fp, 0, fi.size, ptemp);

    rv = apr_brigade_pflatten(bb, &c, &len, p);
    if (rv) {
        _PERR(p, "apr_brigade_pflatten: %s", path);
        return rv;
    }

    *out = c;
    *outlen = len;

    return APR_SUCCESS;
}

/* cleanup */
static apr_status_t mongo_cleanup(void *parms)
{
    mongo_server_config_t *config = (mongo_server_config_t *)parms;

    if (!config) {
        return APR_SUCCESS;
    }

    /* mongo cleanup */
    if (config->cli) {
        delete config->cli;
        config->cli = NULL;
        _PDEBUG(NULL, "Cleanup: mongo database: %s:%d(%d)",
                config->host, config->port, config->timeout);
    }

    /* V8::js cleanup */
    if (config->js) {
        delete config->js;
        config->js = NULL;
#ifdef AP_USE_V8_ISOLATE
        if (config->isolate) {
            config->isolate->Exit();
            config->isolate->Dispose();
        }
#endif
        _PDEBUG(NULL, "Cleanup: V8 Engine");
    }

    if (config->pool) {
        apr_pool_clear(config->pool);
        config->pool = NULL;
    }

    return APR_SUCCESS;
}

/* create server config */
static void *mongo_create_server_config(apr_pool_t *p, server_rec *s)
{
    mongo_server_config_t *config =
        (mongo_server_config_t *)apr_pcalloc(p, sizeof(mongo_server_config_t));

    apr_pool_create(&config->pool, p);

    config->host = NULL;
    config->port = MONGO_CONFIG_UNSET;
    config->timeout = MONGO_CONFIG_UNSET;

    config->cli = NULL;
    config->js = NULL;
#ifdef AP_USE_V8_ISOLATE
    config->isolate = NULL;
#endif

    return (void *)config;
}

/* merge server config */
static void *mongo_merge_server_config(apr_pool_t *p,
                                       void *base_server, void *override_server)
{
    mongo_server_config_t *config =
        (mongo_server_config_t *)apr_pcalloc(p, sizeof(mongo_server_config_t));
    mongo_server_config_t *base = (mongo_server_config_t *)base_server;
    mongo_server_config_t *override  = (mongo_server_config_t *)override_server;

    config->pool = base->pool;

    if (override->host) {
        config->host = override->host;
    } else {
        config->host= (char *)MONGO_DEFAULT_HOST;
    }

    if (override->port == MONGO_CONFIG_UNSET) {
        config->port = MONGO_DEFAULT_PORT;
    } else {
        config->port = override->port;
    }

    if (override->timeout == MONGO_CONFIG_UNSET) {
        config->timeout = MONGO_DEFAULT_TIMEOUT;
    } else {
        config->timeout = override->timeout;
    }

    return (void *)config;
}

/* post config */
static int mongo_post_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    const char *userdata_key = "mongo_post_config";
    void *user_data;
    mongo_server_config_t *config;

    apr_pool_userdata_get(&user_data, userdata_key, s->process->pool);
    if (!user_data) {
        apr_pool_userdata_set(
            (const void *)(1), userdata_key,
            apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    config = (mongo_server_config_t *)ap_get_module_config(
        s->module_config, &mongo_module);

    return OK ;
}

static apr_status_t mongo_init(mongo_server_config_t *config)
{
    /* mongo */
    if (!config->cli) {
        if (!config->host || config->port < 0) {
            return APR_EGENERAL;
        }

        char *connect = apr_psprintf(config->pool, "%s:%d",
                                     config->host, config->port);

        try {
            config->cli = new mongo::DBClientConnection(true, 0,
                                                        config->timeout);
            config->cli->connect(connect);
        } catch(mongo::DBException &e) {
            _PERR(config->pool, "%s: %s", connect, e.what()) ;
            return APR_EGENERAL;
        }

        _PDEBUG(config->pool, "Connectionn mongo database: %s(%d)",
                connect, config->timeout);
    }

    /* V8::js */
    if (!config->js) {
#ifdef AP_USE_V8_ISOLATE
        config->isolate = v8::Isolate::New();
        config->isolate->Enter();
        config->isolate = v8::Isolate::GetCurrent();
        _PDEBUG(p, "v8::isolate => enabled");
#endif

        config->js = new V8::js();

        _PDEBUG(config->pool, "Context V8 Engine");
    }

    /* cleanup */
    apr_pool_cleanup_register(config->pool, (void *)config, mongo_cleanup,
                              apr_pool_cleanup_null);

    return APR_SUCCESS;
}

/* child init */
static void mongo_child_init(apr_pool_t *p, server_rec *s)
{
    mongo_server_config_t *config =
        (mongo_server_config_t *)ap_get_module_config(s->module_config,
                                                      &mongo_module);

    apr_pool_cleanup_register(p, (void *)config, mongo_cleanup,
                              apr_pool_cleanup_null);
}

/* content handler */
static int mongo_handler(request_rec *r)
{
    int retval = OK;

    if (strcmp(r->handler, "mongo-script")) {
        return DECLINED;
    }

    /* server config */
    mongo_server_config_t *config =
        (mongo_server_config_t *)ap_get_module_config(
            r->server->module_config, &mongo_module);

    /* content type */
    r->content_type = MONGO_DEFAULT_CONTENT_TYPE;

    if (!r->header_only) {
        /* init */
        if (mongo_init(config) != APR_SUCCESS) {
            _RERR(r, "initilize faild.");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        //Request parameters.
        apreq_handle_t *apreq = apreq_handle_apache2(r);
        apr_table_t *params = apreq_params(apreq, r->pool);

        //Create a string containing the JavaScript source code.
        const char *src;
        apr_size_t len;
        apr_pool_t *ptemp;
        apr_status_t rv;

        //Read javascript source
        apr_pool_create(&ptemp, r->pool);
        if (mongo_read_file(r->filename, &src, &len,
                            r->pool, ptemp) == APR_SUCCESS) {
            if (!config->js->run(src, len, r, params, &retval, config->cli)) {
                retval = HTTP_INTERNAL_SERVER_ERROR;
            }
        } else {
            _RERR(r, "Failed to read: %s", r->filename);
            retval = HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_pool_clear(ptemp);
    }

    return retval;
}
