#ifndef V8_JS_HPP
#define V8_JS_HPP

/* mongo */
#include "mongo/client/dbclient.h"
#include "mongo/client/connpool.h"

/* v8 */
#include "v8.h"

/* std */
#include <iostream>

/* httpd */
#ifdef __cplusplus
extern "C" {
#endif
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
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

/* json function */
#define V8_MONGO_JSON_OBJECT()                                  \
    v8::Local<v8::Context> context = v8::Context::GetCurrent(); \
    v8::Local<v8::Object> global = context->Global();           \
    v8::Local<v8::Object> json =                                \
        global->Get(v8::String::New("JSON"))->ToObject()

static v8::Local<v8::Value> v8_objectTojson(v8::Handle<v8::Value> obj)
{
    V8_MONGO_JSON_OBJECT();

    v8::Local<v8::Function> json_stringify =
        v8::Local<v8::Function>::Cast(json->Get(v8::String::New("stringify")));

    return json_stringify->Call(json, 1, &obj);
}

static v8::Local<v8::Value> v8_jsonToobject(v8::Handle<v8::Value> str)
{
    V8_MONGO_JSON_OBJECT();

    v8::Local<v8::Function> json_parse =
        v8::Local<v8::Function>::Cast(json->Get(v8::String::New("parse")));

    return json_parse->Call(json, 1, &str);
}

/* callback function */
/* ap function */
#define V8_MONGO_AP_WRAP(num)                                       \
    v8::HandleScope scope;                                          \
    v8::Local<v8::Object> self = args.Holder();                     \
    v8::Local<v8::External> wrap =                                  \
        v8::Local<v8::External>::Cast(self->GetInternalField(num))

#define V8_MONGO_AP_REQUEST()                                   \
    request_rec *r = static_cast<request_rec*>(wrap->Value())

static v8::Handle<v8::Value> v8_ap_log(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_MONGO_AP_WRAP(0);
    V8_MONGO_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "%s", *value);

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_ap_rputs(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_MONGO_AP_WRAP(0);
    V8_MONGO_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    ap_rputs(*value, r);

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_ap_content_type(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_MONGO_AP_WRAP(0);
    V8_MONGO_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    if (value.length() > 0) {
        char *ct = apr_psprintf(r->pool, "%s", *value);
        if (ct) {
            ap_set_content_type(r, ct);
        }
    }

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_ap_dirname(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    v8::String::Utf8Value value(args[0]->ToString());

    if (value.length() == 0) {
        return v8::Undefined();
    }

    char *s = *value + value.length() - 1;

    while (s && *s == '/') {
        *s = '\0';
        s = *value + strlen(*value) - 1;
    }

    s = strrchr(*value, '/');
    if (s != NULL) {
        if (s == *value) {
            return v8::String::New("/");
        }
        *s = '\0';
    }

    return v8::String::New(*value);
}

static v8::Handle<v8::Value> v8_ap_include(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_MONGO_AP_WRAP(0);
    V8_MONGO_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    apr_status_t rv;
    apr_file_t *fp;
    apr_finfo_t fi;
    apr_size_t bytes;
    void *src;

    rv = apr_file_open(&fp, *value,
                       APR_READ | APR_BINARY | APR_XTHREAD, APR_OS_DEFAULT,
                       r->pool);
    if (rv != APR_SUCCESS) {
        _RERR(r, "file open: %s", *value);
        return scope.Close(v8::Undefined());
    }

    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, fp);
    if (rv != APR_SUCCESS || fi.size <= 0) {
        _RERR(r, "file info: %s", *value);
        apr_file_close(fp);
        return scope.Close(v8::Undefined());
    }

    src = apr_palloc(r->pool, fi.size);
    if (!src) {
        _RERR(r, "apr_palloc");
        apr_file_close(fp);
        return scope.Close(v8::Undefined());
    }

    rv = apr_file_read_full(fp, src, fi.size, &bytes);
    if (rv != APR_SUCCESS || bytes != fi.size) {
        _RERR(r, "file read: %s", *value);
        apr_file_close(fp);
        return scope.Close(v8::Undefined());
    }

    apr_file_close(fp);

    v8::TryCatch try_catch;
    v8::Handle<v8::String> source = v8::String::New((char *)src, fi.size);
    v8::Handle<v8::Script> script = v8::Script::Compile(source);
    v8::Handle<v8::Value> result = script->Run();

    if (result.IsEmpty()) {
        v8::String::Utf8Value error(try_catch.Exception());
        _RERR(r, "include(%s) Failed: %s", r->filename, *error);
        return scope.Close(v8::Undefined());
    } else {
        return scope.Close(result);
    }
}

static v8::Handle<v8::Value> v8_ap_request(const v8::Arguments& args)
{
    if (args.Length() < 1) {
        return v8::Undefined();
    }

    V8_MONGO_AP_WRAP(0);
    V8_MONGO_AP_REQUEST();

    v8::String::Utf8Value value(args[0]->ToString());

    const char *val;

    if (strcmp(*value, "method") == 0) {
        val = r->method;
    } else if (strcmp(*value, "uri") == 0) {
        request_rec *prev = r->prev;
        while (prev != NULL) {
            r = prev;
            prev = r->prev;
        }
        val = r->uri;
    } else if (strcmp(*value, "filename") == 0) {
        val = r->filename;
    } else if (strcmp(*value, "remote_ip") == 0) {
        val = r->connection->remote_ip;
    } else if (strcmp(*value, "hostname") == 0) {
        val = r->hostname;
    } else {
        val = NULL;
    }

    if (val) {
        return scope.Close(v8::String::New(val));
    }

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_ap_header(const v8::Arguments& args)
{
    V8_MONGO_AP_WRAP(0);
    V8_MONGO_AP_REQUEST();

    if (args.Length() >= 1) {
        v8::String::Utf8Value value(args[0]->ToString());

        const char *header = apr_table_get(r->headers_in, *value);

        if (header) {
            return scope.Close(v8::String::New(header));
        }
    } else {
        v8::Handle<v8::Array> arr(v8::Array::New());

        const apr_array_header_t *header = apr_table_elts(r->headers_in);
        apr_table_entry_t *elts = (apr_table_entry_t *)header->elts;

        for (int i = 0; i < header->nelts; i++) {
            arr->Set(i, v8::String::New(elts[i].key));
        }

        return scope.Close(arr);
    }

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_ap_response_header(const v8::Arguments& args)
{
    V8_MONGO_AP_WRAP(0);
    V8_MONGO_AP_REQUEST();

    if (args.Length() < 2) {
        return scope.Close(v8::Undefined());
    }

    v8::String::Utf8Value key(args[0]->ToString());
    v8::String::Utf8Value value(args[1]->ToString());

    apr_table_set(r->headers_out, *key, *value);

    return scope.Close(v8::Boolean::New(true));
}

static v8::Handle<v8::Value> v8_ap_response_code(const v8::Arguments& args)
{
    V8_MONGO_AP_WRAP(2);

    if (args.Length() >= 1 && args[0]->IsNumber()) {
        int *code = (int *)(wrap->Value());
        *code = args[0]->ToInt32()->Int32Value();
        return scope.Close(v8::Boolean::New(true));
    }

    return scope.Close(v8::Undefined());
}

static v8::Handle<v8::Value> v8_ap_params(const v8::Arguments& args)
{
    V8_MONGO_AP_WRAP(1);

    v8::String::Utf8Value value(args[0]->ToString());

    apr_table_t *tbl = static_cast<apr_table_t*>(wrap->Value());
    if (!tbl) {
        return v8::Undefined();
    }

    if (args.Length() >= 1) {
        const char *param = apr_table_get(tbl, *value);

        if (param) {
            return scope.Close(v8::String::New(param));
        }
    } else {
        v8::Handle<v8::Array> arr(v8::Array::New());

        const apr_array_header_t *arr_tbl = apr_table_elts(tbl);
        apr_table_entry_t *elts = (apr_table_entry_t *)arr_tbl->elts;

        for (int i = 0; i < arr_tbl->nelts; i++) {
            arr->Set(i, v8::String::New(elts[i].key));
        }

        return scope.Close(arr);
    }

    return scope.Close(v8::Undefined());
}

/* mongo function */
static v8::Handle<v8::Value> v8_mongo_toJson(const v8::Arguments& args)
{
    if (args.Length() < 1 || !args[0]->IsObject()) {
        return v8::Undefined();
    }

    V8_MONGO_AP_WRAP(0);

    v8::Handle<v8::Value> arg = args[0];

    v8::TryCatch try_catch;
    v8::Local<v8::Value> result = v8_objectTojson(arg);

    if (result.IsEmpty()) {
        v8::String::Utf8Value error(try_catch.Exception());
        V8_MONGO_AP_REQUEST();
        _RERR(r, "toJson(%s) Failed: %s", r->filename, *error);
        return scope.Close(v8::Undefined());
    } else {
        return scope.Close(result);
    }
}

static v8::Handle<v8::Value> v8_mongo_fromJson(const v8::Arguments& args)
{
    if (args.Length() < 1 || !args[0]->IsString()) {
        return v8::Undefined();
    }

    V8_MONGO_AP_WRAP(0);

    v8::Handle<v8::Value> arg = args[0];

    v8::TryCatch try_catch;
    v8::Handle<v8::Value> result = v8_jsonToobject(arg);
    if (result.IsEmpty()) {
        v8::String::Utf8Value error(try_catch.Exception());
        V8_MONGO_AP_REQUEST();
        _RERR(r, "fromJson(%s) Failed: %s", r->filename, *error);
        return scope.Close(v8::Undefined());
    } else {
        return scope.Close(result);
    }
}

static v8::Handle<v8::Value> v8_mongo_unicode_escape(const v8::Arguments& args)
{
    if (args.Length() < 1 && !args[0]->IsString()) {
        return v8::Undefined();
    }

    V8_MONGO_AP_WRAP(0);
    V8_MONGO_AP_REQUEST();

    v8::String::Value value(args[0]);
    std::string buf;

    const char digits[] = "0123456789abcdef";

    int pos = 0;
    int len = value.length();
    uint16_t u16;

    while (pos < len) {
        u16 = (*value)[pos++];
        switch (u16) {
            case '"':
                //buf += "\u0022";
                buf += "\"";
                break;
            case '\\':
                buf += "\\\\";
                break;
            case '/':
                //buf += '/';
                buf += "\\/";
                break;
            case '\b':
                buf += "\\b";
                break;
            case '\f':
                buf += "\\f";
                break;
            case '\n':
                buf += "\\n";
                break;
            case '\r':
                buf += "\\r";
                break;
            case '\t':
                buf += "\\t";
                break;
            case '<':
                //buf += "\\u003C";
                buf += "<";
                break;
            case '>':
                //buf += "\\u003E";
                buf += ">";
                break;
            case '&':
                //buf += "\\u0026";
                buf += "&";
                break;
            case '\'':
                //buf += "\\u0027";
                buf += "'";;
                break;
            default:
                if (u16 >= ' ' && (u16 & 127) == u16) {
                    buf += (unsigned char)u16;
                } else {
                    buf += "\\u";
                    u16 = (((u16 & 0xf) << 12) |
                           (((u16 >> 4) & 0xf) << 8) |
                           (((u16 >> 8) & 0xf) << 4) |
                           ((u16 >> 12) & 0xf));
                    buf += digits[u16 & ((1 << 4) - 1)];
                    u16 >>= 4;
                    buf += digits[u16 & ((1 << 4) - 1)];
                    u16 >>= 4;
                    buf += digits[u16 & ((1 << 4) - 1)];
                    u16 >>= 4;
                    buf += digits[u16 & ((1 << 4) - 1)];
                }
                break;
        }
    }

    return scope.Close(v8::String::New(buf.c_str(), buf.length()));
}

#define V8_MONGO_REQUEST_CLIENT()                                       \
    v8::HandleScope scope;                                              \
    v8::Local<v8::Object> self = args.Holder();                         \
    v8::Local<v8::External> request_wrap =                              \
        v8::Local<v8::External>::Cast(self->GetInternalField(0));       \
    v8::Local<v8::External> client_wrap =                               \
        v8::Local<v8::External>::Cast(self->GetInternalField(1));       \
    request_rec *r = static_cast<request_rec *>(request_wrap->Value()); \
    mongo::DBClientConnection *cli =                                    \
        static_cast<mongo::DBClientConnection *>(client_wrap->Value())

#define V8_MONGO_ARGS_REQUIRED(num, msg)                 \
    if (args.Length() < num) {                           \
        _PERR(NULL, msg" required parameters(%d)", num); \
        return v8::Undefined();                          \
    }

#define V8_MONGO_ARGS_BOOLEAN_TRUE(num, val)      \
    if (args[num]->ToBoolean()->BooleanValue()) { \
        val = true;                               \
    }

#define V8_MONGO_ARGS_NUMBER_INT32(num, val)      \
    if (args[num]->IsNumber()) {                  \
        val = args[num]->ToInt32()->Int32Value(); \
    }

#define V8_MONGO_ARGS_OBJECT_TO_JSON(num, val, msg)             \
    if (args[num]->IsObject()) {                                \
        val = v8_objectTojson(args[num]);                       \
        if (val.IsEmpty() || !val->IsString()) {                \
            v8::String::Utf8Value error(try_catch.Exception()); \
            _RERR(r, msg" %s: %s", *error, r->filename);        \
            return scope.Close(v8::Undefined());                \
        }                                                       \
    }

#define V8_MONGO_ARGS_OBJECT_TO_JSON_REQUIRED(num, val, msg) \
    V8_MONGO_ARGS_OBJECT_TO_JSON(num, val, msg)              \
    else {                                                   \
        _RERR(r, msg" is not object: %s", r->filename);      \
        return scope.Close(v8::Undefined());                 \
    }

#define V8_MONGO_ARGS_STRING(num, val, msg)             \
    if (!args[num]->IsString()) {                       \
        _RERR(r, msg" is not string: %s", r->filename); \
        return scope.Close(v8::Undefined());            \
    }                                                   \
    val = args[num]

#define V8_MONGO_RETURN_ARGS_UNKNOWN(num, msg)   \
    _RERR(r, msg" unknown parameters(%d)", num); \
    return scope.Close(v8::Undefined());

#define V8_MONGO_UTF8VALUE(utf8, val, msg)         \
    v8::String::Utf8Value utf8(val->ToString());   \
    if (utf8.length() == 0) {                      \
        _RERR(r, msg" is empty: %s", r->filename); \
        return scope.Close(v8::Undefined());       \
    }

#define V8_MONGO_UTF8VALUE_NAMESPACE(utf8, val, msg)           \
    V8_MONGO_UTF8VALUE(utf8, val, msg);                        \
    if (strchr(*ns, '.') == NULL) {                            \
        _RERR(r, msg" namespace is invalid: %s", r->filename); \
        return scope.Close(v8::Undefined());                   \
    }

#define V8_MONGO_UTF8VALUE_JSON_REQUIRED(utf8, val, msg) \
    V8_MONGO_UTF8VALUE(utf8, val, msg);                  \
    if (strcmp(*utf8, "{}") == 0) {                      \
        _RERR(r, msg" is empty: %s", r->filename);       \
        return scope.Close(v8::Undefined());             \
    }

#define V8_MONGO_TRY() try {
#define V8_MONGO_CATCH(msg)                    \
    } catch(mongo::MsgAssertionException &e) { \
        _RERR(r, msg": %s", e.what());         \
        return scope.Close(v8::Undefined());   \
    } catch(mongo::UserException &e) {         \
        _RERR(r, msg": %s", e.what());         \
        return scope.Close(v8::Undefined());   \
    } catch(mongo::DBException &e) {           \
        _RERR(r, ": %s", e.what());            \
        return scope.Close(v8::Undefined());   \
    }

#define V8_MONGO_SAFE(safe, msg)                                              \
    if (safe) {                                                               \
        _RDEBUG(r, msg" getLastError");                                       \
        if (!cli->getLastError().empty()) {                                   \
            _RERR(r, msg" %s: %s", cli->getLastError().c_str(), r->filename); \
            return scope.Close(v8::Undefined());                              \
        }                                                                     \
    }

#define V8_MONGO_RETURN_BSONOBJ_TO_OBJECT(bson, msg)                    \
    v8::Handle<v8::Value> result                                        \
        = v8_jsonToobject(v8::String::New(bson.jsonString().c_str()));  \
    if (result.IsEmpty()) {                                             \
        v8::String::Utf8Value error(try_catch.Exception());             \
        _RERR(r, msg"%s: %s", *error, r->filename);                     \
        return scope.Close(v8::Undefined());                            \
    }                                                                   \
    return scope.Close(result)


//object mongo.insert( string ns, object obj
//                     [, boolean retval = false, boolean safe = false] )
static v8::Handle<v8::Value> v8_mongo_insert(const v8::Arguments& args)
{
    V8_MONGO_ARGS_REQUIRED(2, "insert");
    V8_MONGO_REQUEST_CLIENT();

    v8::TryCatch try_catch;
    v8::Local<v8::Value> _ns;
    v8::Local<v8::Value> _obj;
    bool retval = false;
    bool safe = false;

    //args
    switch (args.Length()) {
        case 4:
            V8_MONGO_ARGS_BOOLEAN_TRUE(3, safe);
        case 3:
            V8_MONGO_ARGS_BOOLEAN_TRUE(2, retval);
        case 2:
            V8_MONGO_ARGS_OBJECT_TO_JSON_REQUIRED(1, _obj, "insert obj");
        case 1:
            V8_MONGO_ARGS_STRING(0, _ns, "insert namespace");
            break;
        default:
            V8_MONGO_RETURN_ARGS_UNKNOWN(4, "insert");
    }

    V8_MONGO_UTF8VALUE_NAMESPACE(ns, _ns, "insert");
    V8_MONGO_UTF8VALUE_JSON_REQUIRED(obj, _obj, "insert obj");

    V8_MONGO_TRY();

    //insert
    if (retval) {
        mongo::BSONObjBuilder builder;
        builder.genOID();
        builder.appendElements(mongo::fromjson(*obj));
        mongo::BSONObj bson_obj = builder.obj();

        cli->insert(*ns, bson_obj);

        V8_MONGO_SAFE(safe, "insert");

        V8_MONGO_RETURN_BSONOBJ_TO_OBJECT(bson_obj, "insert");
    } else {
        mongo::BSONObj bson_obj = mongo::fromjson(*obj);

        cli->insert(*ns, bson_obj);

        V8_MONGO_SAFE(safe, "insert");
    }

    V8_MONGO_CATCH("insert");

    return scope.Close(v8::Boolean::New(true));
}

//object mongo.findOne( string ns
//                      [, object query = {}, object fields = {} ] )
static v8::Handle<v8::Value> v8_mongo_findOne(const v8::Arguments& args)
{
    V8_MONGO_ARGS_REQUIRED(1, "findOne");
    V8_MONGO_REQUEST_CLIENT();

    v8::TryCatch try_catch;
    v8::Local<v8::Value> _ns;
    v8::Local<v8::Value> _query;
    v8::Local<v8::Value> _fields;

    //args
    switch (args.Length()) {
        case 3:
            V8_MONGO_ARGS_OBJECT_TO_JSON(2, _fields, "findOne fields");
        case 2:
            V8_MONGO_ARGS_OBJECT_TO_JSON(1, _query, "findOne query");
        case 1:
            V8_MONGO_ARGS_STRING(0, _ns, "findOne namespace");
            break;
        default:
            V8_MONGO_RETURN_ARGS_UNKNOWN(3, "findOne");
    }

    V8_MONGO_UTF8VALUE_NAMESPACE(ns, _ns, "findOne");

    V8_MONGO_TRY();

    //query
    mongo::BSONObj bson_query;
    if (!_query.IsEmpty()) {
        V8_MONGO_UTF8VALUE(query, _query, "findOne query");
        bson_query = mongo::fromjson(*query);
    } else {
        bson_query = mongo::fromjson("{}");
    }

    //fields
    mongo::BSONObj bson_fields;
    if (!_fields.IsEmpty()) {
        V8_MONGO_UTF8VALUE(fields, _fields, "findOne fields");
        bson_fields = mongo::fromjson(*fields);
    } else {
        bson_fields = mongo::fromjson("{}");
    }

    //findOne
    mongo::BSONObj obj = cli->findOne(*ns, bson_query, &bson_fields);
    if (!obj.isEmpty()) {
        V8_MONGO_RETURN_BSONOBJ_TO_OBJECT(obj, "findOne");
    }

    V8_MONGO_CATCH("fineOne");

    return scope.Close(v8::Undefined());
}

//array mongo.find( string ns
//                  [, object query = {},  int limit = 0, int skip = 0,
//                     object fields = {}, object orderby = null ] )
static v8::Handle<v8::Value> v8_mongo_find(const v8::Arguments& args)
{
    V8_MONGO_ARGS_REQUIRED(1, "find");
    V8_MONGO_REQUEST_CLIENT();

    v8::TryCatch try_catch;
    v8::Local<v8::Value> _ns;
    v8::Local<v8::Value> _query;
    int limit = 0;
    int skip = 0;
    v8::Local<v8::Value> _fields;
    v8::Local<v8::Value> _orderby;

    //args
    switch (args.Length()) {
        case 6:
            V8_MONGO_ARGS_OBJECT_TO_JSON(5, _orderby, "find orderby");
        case 5:
            V8_MONGO_ARGS_OBJECT_TO_JSON(4, _fields, "find fields");
        case 4:
            V8_MONGO_ARGS_NUMBER_INT32(3, skip);
        case 3:
            V8_MONGO_ARGS_NUMBER_INT32(2, limit);
        case 2:
            V8_MONGO_ARGS_OBJECT_TO_JSON(1, _query, "find query");
        case 1:
            V8_MONGO_ARGS_STRING(0, _ns, "find namespace");
            break;
        default:
            V8_MONGO_RETURN_ARGS_UNKNOWN(5, "find");
    }

    V8_MONGO_UTF8VALUE_NAMESPACE(ns, _ns, "find");
    v8::Handle<v8::Array> return_value(v8::Array::New());

    V8_MONGO_TRY();

    //query
    mongo::BSONObj bson_query;
    if (_orderby.IsEmpty()) {
        if (!_query.IsEmpty()) {
            V8_MONGO_UTF8VALUE(query, _query, "find query");
            bson_query = mongo::fromjson(*query);
        } else {
            bson_query = mongo::fromjson("{}");
        }
    } else {
        //orderby
        mongo::BSONObjBuilder builder;
        V8_MONGO_UTF8VALUE(orderby, _orderby, "find orderby");
        if (!_query.IsEmpty()) {
            V8_MONGO_UTF8VALUE(query, _query, "find query");
            builder.append("query", mongo::fromjson(*query));
        } else {
            builder.append("query", mongo::fromjson("{}"));
        }
        builder.append("orderby", mongo::fromjson(*orderby));
        bson_query = builder.obj();
    }

    //fields
    mongo::BSONObj bson_fields;
    if (!_fields.IsEmpty()) {
        V8_MONGO_UTF8VALUE(fields, _fields, "find fields");
        bson_fields = mongo::fromjson(*fields);
    } else {
        bson_fields = mongo::fromjson("{}");
    }

    //find
    std::auto_ptr<mongo::DBClientCursor> cursor =
        cli->query(*ns, bson_query, limit, skip, &bson_fields);
    int i = 0;
    while (cursor->more()) {
        mongo::BSONObj obj = cursor->next();
        v8::Handle<v8::Value> result =
            v8_jsonToobject(v8::String::New(obj.jsonString().c_str()));
        if (result.IsEmpty()) {
            return_value->Set(i, v8::Undefined());
        } else {
            return_value->Set(i, result);
        }
        i++;
    }

    V8_MONGO_CATCH("find");

    return scope.Close(return_value);
}

//boolean mongo.update( string ns, object query, object obj
//                      [, boolean upsert = false, boolean multi = false,
//                         boolean safe = false ] )
static v8::Handle<v8::Value> v8_mongo_update(const v8::Arguments& args)
{
    V8_MONGO_ARGS_REQUIRED(3, "update");
    V8_MONGO_REQUEST_CLIENT();

    v8::TryCatch try_catch;
    v8::Local<v8::Value> _ns;
    v8::Local<v8::Value> _query;
    v8::Local<v8::Value> _obj;
    bool upsert = false;
    bool multi = false;
    bool safe = false;

    //args
    switch (args.Length()) {
        case 6:
            V8_MONGO_ARGS_BOOLEAN_TRUE(5, safe);
        case 5:
            V8_MONGO_ARGS_BOOLEAN_TRUE(4, multi);
        case 4:
            V8_MONGO_ARGS_BOOLEAN_TRUE(3, upsert);
        case 3:
            V8_MONGO_ARGS_OBJECT_TO_JSON_REQUIRED(2, _obj, "update obj");
        case 2:
            V8_MONGO_ARGS_OBJECT_TO_JSON_REQUIRED(1, _query, "update query");
        case 1:
            V8_MONGO_ARGS_STRING(0, _ns, "update namespace");
            break;
        default:
            V8_MONGO_RETURN_ARGS_UNKNOWN(5, "update");;
    }

    V8_MONGO_UTF8VALUE_NAMESPACE(ns, _ns, "update");
    V8_MONGO_UTF8VALUE(query, _query, "update query");
    V8_MONGO_UTF8VALUE(obj, _obj, "update obj");

    V8_MONGO_TRY();

    //update
    mongo::BSONObj bson_query = mongo::fromjson(*query);
    mongo::BSONObj bson_obj = mongo::fromjson(*obj);

    cli->update(*ns, bson_query, bson_obj, upsert, multi);

    V8_MONGO_SAFE(safe, "update");

    V8_MONGO_CATCH("update");

    return scope.Close(v8::Boolean::New(true));
}

//boolean mongo.remove( string ns, object query
//                      [, boolean justOne = false, boolean safe = false ] )
static v8::Handle<v8::Value> v8_mongo_remove(const v8::Arguments& args)
{
    V8_MONGO_ARGS_REQUIRED(2, "remove");
    V8_MONGO_REQUEST_CLIENT();

    v8::TryCatch try_catch;
    v8::Local<v8::Value> _ns;
    v8::Local<v8::Value> _query;
    bool justOne =false;
    bool safe =false;

    //args
    switch (args.Length()) {
        case 4:
            V8_MONGO_ARGS_BOOLEAN_TRUE(3, safe);
        case 3:
            V8_MONGO_ARGS_BOOLEAN_TRUE(2, justOne);
        case 2:
            V8_MONGO_ARGS_OBJECT_TO_JSON_REQUIRED(1, _query, "remove query");
        case 1:
            V8_MONGO_ARGS_STRING(0, _ns, "remove namespace");
            break;
        default:
            V8_MONGO_RETURN_ARGS_UNKNOWN(4, "remove");
    }

    V8_MONGO_UTF8VALUE_NAMESPACE(ns, _ns, "remove");
    V8_MONGO_UTF8VALUE(query, _query, "remove query");

    V8_MONGO_TRY();

    //remove
    mongo::BSONObj bson_query = mongo::fromjson(*query);

    cli->remove(*ns, bson_query, justOne);

    V8_MONGO_SAFE(safe, "remove");

    V8_MONGO_CATCH("remove");

    return scope.Close(v8::Boolean::New(true));
}

//boolean|object mongo.findAndModify( string ns
//                                    [, object query = {},
//                                       object sort = {},
//                                       boolean remove = false,
//                                       object update = null,
//                                       boolean retval = false,
//                                       object fields = {},
//                                       boolean upsert = false,
//                                       boolean safe = false ] )
static v8::Handle<v8::Value> v8_mongo_findAndModify(const v8::Arguments& args)
{
    V8_MONGO_ARGS_REQUIRED(1, "findAndModify");
    V8_MONGO_REQUEST_CLIENT();

    v8::TryCatch try_catch;
    v8::Local<v8::Value> _ns;
    v8::Local<v8::Value> _query;
    v8::Local<v8::Value> _sort;
    bool remove = false;
    v8::Local<v8::Value> _update;
    bool retval = false;
    v8::Local<v8::Value> _fields;
    bool upsert = false;
    bool safe = false;

    //args
    switch (args.Length()) {
        case 9:
            V8_MONGO_ARGS_BOOLEAN_TRUE(8, safe);
        case 8:
            V8_MONGO_ARGS_BOOLEAN_TRUE(7, upsert);
        case 7:
            V8_MONGO_ARGS_OBJECT_TO_JSON(6, _fields, "findAndModify fields");
        case 6:
            V8_MONGO_ARGS_BOOLEAN_TRUE(5, retval);
        case 5:
            V8_MONGO_ARGS_OBJECT_TO_JSON(4, _update, "findAndModify update");
        case 4:
            V8_MONGO_ARGS_BOOLEAN_TRUE(3, remove);
        case 3:
            V8_MONGO_ARGS_OBJECT_TO_JSON(2, _sort, "findAndModify sort");
        case 2:
            V8_MONGO_ARGS_OBJECT_TO_JSON(1, _query, "findAndModify query");
        case 1:
            V8_MONGO_ARGS_STRING(0, _ns, "findAndModify namespace");
            break;
        default:
            V8_MONGO_RETURN_ARGS_UNKNOWN(9, "findAndModify");
    }

    V8_MONGO_UTF8VALUE(ns, _ns, "findAndModify namespace");

    //db / collection
    char *s = strchr(*ns, '.');
    if (s == NULL) {
        _RERR(r, "findAndModify namespace is invalid: %s", r->filename);
        return scope.Close(v8::Undefined());
    }
    char *collection = apr_psprintf(r->pool, "%s", s + 1);
    *s = '\0';
    char *db = apr_psprintf(r->pool, "%s", *ns);

    V8_MONGO_TRY();

    mongo::BSONObjBuilder command;

    command.append("findAndModify", collection);

    //query
    if (!_query.IsEmpty()) {
        V8_MONGO_UTF8VALUE(query, _query, "findAndModify query");
        command.append("query", mongo::fromjson(*query));
    }

    //sort
    if (!_sort.IsEmpty()) {
        V8_MONGO_UTF8VALUE(sort, _sort, "findAndModify sort");
        command.append("sort", mongo::fromjson(*sort));
    }

    //remove
    if (remove) {
        command.append("remove", true);
    }

    //update
    if (!_update.IsEmpty()) {
        V8_MONGO_UTF8VALUE(update, _update, "findAndModify update");
        command.append("update", mongo::fromjson(*update));
    }

    //retval
    if (retval) {
        command.append("new", true);
    }

    //fields
    if (!_fields.IsEmpty()) {
        V8_MONGO_UTF8VALUE(fields, _fields, "findAndModify fields");
        command.append("fields", mongo::fromjson(*fields));
    }

    //upsert
    if (upsert) {
        command.append("upsert", true);
    }

    mongo::BSONObj bson_obj;

    if (!cli->runCommand(db, command.obj(), bson_obj)) {
        _RERR(r, "findAndModify: runCommand %s: %s",
              cli->getLastError().c_str(), r->filename);
        return scope.Close(v8::Undefined());
    }

    V8_MONGO_SAFE(safe, "findAndModify");

    if (retval && !bson_obj.isEmpty() && bson_obj.hasField("value")) {
        mongo::BSONObj bson_value = bson_obj.getObjectField("value");
        V8_MONGO_RETURN_BSONOBJ_TO_OBJECT(bson_value, "findAndModify");
    }

    V8_MONGO_CATCH("remove");

    return scope.Close(v8::Boolean::New(true));
}

/* V8::js class */
namespace V8 {
class js
{
public:
    js() {
        if (!v8::Context::InContext()) {
            context_enter_ = true;
            global_context_ = v8::Context::New();
            global_context_->Enter();
            context_ = v8::Local<v8::Context>::New(global_context_);
        } else {
            context_enter_ = false;
            context_ = v8::Context::GetCurrent();
        }

        v8::Context::Scope scope(context_);

        //ap object template.
        v8::Handle<v8::ObjectTemplate> ap_tmpl = v8::ObjectTemplate::New();
        ap_tmpl->SetInternalFieldCount(3);

        ap_tmpl->Set(v8::String::New("log"),
                     v8::FunctionTemplate::New(v8_ap_log));
        ap_tmpl->Set(v8::String::New("dirname"),
                     v8::FunctionTemplate::New(v8_ap_dirname));
        ap_tmpl->Set(v8::String::New("include"),
                     v8::FunctionTemplate::New(v8_ap_include));

        //Request function.
        ap_tmpl->Set(v8::String::New("request"),
                     v8::FunctionTemplate::New(v8_ap_request));

        //Header function.
        ap_tmpl->Set(v8::String::New("header"),
                     v8::FunctionTemplate::New(v8_ap_header));

        //Parameter function.
        ap_tmpl->Set(v8::String::New("params"),
                     v8::FunctionTemplate::New(v8_ap_params));

        //Response function.
        ap_tmpl->Set(v8::String::New("content_type"),
                     v8::FunctionTemplate::New(v8_ap_content_type));
        ap_tmpl->Set(v8::String::New("rputs"),
                     v8::FunctionTemplate::New(v8_ap_rputs));
        ap_tmpl->Set(v8::String::New("rheader"),
                     v8::FunctionTemplate::New(v8_ap_response_header));
        ap_tmpl->Set(v8::String::New("rcode"),
                     v8::FunctionTemplate::New(v8_ap_response_code));

        ap_ = ap_tmpl->NewInstance();

        //mongo object template.
        v8::Handle<v8::ObjectTemplate> mongo_tmpl = v8::ObjectTemplate::New();
        mongo_tmpl->SetInternalFieldCount(2);

        //mongoDB function.
        mongo_tmpl->Set(v8::String::New("toJson"),
                        v8::FunctionTemplate::New(v8_mongo_toJson));
        mongo_tmpl->Set(v8::String::New("fromJson"),
                        v8::FunctionTemplate::New(v8_mongo_fromJson));
        mongo_tmpl->Set(v8::String::New("unicode_escape"),
                        v8::FunctionTemplate::New(v8_mongo_unicode_escape));

        mongo_tmpl->Set(v8::String::New("findOne"),
                        v8::FunctionTemplate::New(v8_mongo_findOne));
        mongo_tmpl->Set(v8::String::New("find"),
                        v8::FunctionTemplate::New(v8_mongo_find));
        mongo_tmpl->Set(v8::String::New("insert"),
                        v8::FunctionTemplate::New(v8_mongo_insert));
        mongo_tmpl->Set(v8::String::New("update"),
                        v8::FunctionTemplate::New(v8_mongo_update));
        mongo_tmpl->Set(v8::String::New("remove"),
                        v8::FunctionTemplate::New(v8_mongo_remove));
        mongo_tmpl->Set(v8::String::New("findAndModify"),
                        v8::FunctionTemplate::New(v8_mongo_findAndModify));

        mongo_tmpl->Set(v8::String::New("ap"), ap_);

        mongo_ = mongo_tmpl->NewInstance();
        context_->Global()->Set(v8::String::New("mongo"), mongo_);
    }

    ~js() {
        if (context_enter_) {
            global_context_->DetachGlobal();
            global_context_->Exit();
            global_context_.Dispose();
        }
    }

    bool run(const char *src, apr_size_t len, request_rec *r,
             apr_table_t *params, int *code, mongo::DBClientConnection *cli) {
        v8::TryCatch try_catch;

        ap_->SetInternalField(0, v8::External::New(r));
        ap_->SetInternalField(1, v8::External::New(params));
        ap_->SetInternalField(2, v8::External::New(code));

        mongo_->SetInternalField(0, v8::External::New(r));
        mongo_->SetInternalField(1, v8::External::New(cli));
        //mongo_->SetInternalField(2, v8::External::New(params));

        v8::Handle<v8::String> source = v8::String::New(src, len);

        //Compile the source code.
        v8::Handle<v8::Script> script = v8::Script::Compile(source);
        if (script.IsEmpty()) {
            v8::String::Utf8Value error(try_catch.Exception());
            _RERR(r, "Script(%s) Failed: %s", r->filename, *error);
            return false;
        }

        //Run the script to get the result.
        v8::Handle<v8::Value> result = script->Run();
        if (result.IsEmpty()) {
            v8::String::Utf8Value error(try_catch.Exception());
            _RERR(r, "Script(%s) Failed: %s", r->filename, *error);
            return false;
        }

        return true;
    }

private:
    bool context_enter_;

    v8::HandleScope scope_;
    v8::Persistent<v8::Context> global_context_;

    v8::Handle<v8::Object> ap_;
    v8::Handle<v8::Object> mongo_;
    v8::Local<v8::Context> context_;
};
}

#endif // V8_JS_HPP
