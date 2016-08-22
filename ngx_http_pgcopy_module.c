/*
 * Copyright (C) Anton Riabchevskiy (AntonRiab)
 * All rights reserved.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <libpq-fe.h>
//#include "libpq-int.h"

#define PGCOPY_DEBUG

#include "ngx_http_pgcopy_module.h"

/*
 *    <defenition>
 *    <configuration>
 */
static ngx_int_t ngx_http_pgcopy_init(ngx_conf_t *cf);
void *ngx_http_pgcopy_srv_conf(ngx_conf_t *cf);
void *ngx_http_pgcopy_loc_conf(ngx_conf_t *cf);
char *ngx_http_pgcopy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

char *ngx_http_conf_pgcopy_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_conf_pgcopy_query(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/*
 *     </configuration>
 *     <phase_handlers>
 */
static ngx_int_t ngx_http_pgcopy_init_access_handler(ngx_http_request_t *r);

ngx_int_t ngx_pgcopy_start_pooling(ngx_http_request_t *r);
ngx_int_t ngx_pgcopy_need_made(ngx_http_request_t *r);
static ngx_int_t ngx_http_pgcopy_access_handler(ngx_http_request_t *r);

ngx_int_t ngx_pgcopy_content_handler(ngx_http_request_t *r);
/*
 *     </phase_handlers>
 *     <upstream>
 */
ngx_int_t ngx_pgcopy_upstream_init(ngx_http_request_t *r, ngx_http_pgcopy_ctx_t *ctx);
ngx_int_t ngx_pgcopy_upstream_test_connect(ngx_connection_t *c);
ngx_int_t ngx_pgcopy_upstream_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf);

ngx_int_t ngx_pgcopy_upstream_get_peer_begin_connect(ngx_peer_connection_t *pc, void *data);
void ngx_pgcopy_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

void ngx_pgcopy_query_arbiter(ngx_http_request_t *r, ngx_http_upstream_t *u);
void ngx_pgcopy_out(ngx_http_request_t *r, ngx_http_upstream_t *u);
void ngx_pgcopy_in(ngx_http_request_t *r, ngx_http_upstream_t *u);
/*
 *    </upstream>
 *    <empty_handler_to_avoid_core_dump>
 */

ngx_int_t ngx_pgcopy_create_request(ngx_http_request_t *r);
ngx_int_t ngx_pgcopy_reinit_request(ngx_http_request_t *r);
ngx_int_t ngx_pgcopy_process_header(ngx_http_request_t *r);
void ngx_http_pgcopy_abort_request(ngx_http_request_t *r);

void ngx_pgcopy_empty_handler(ngx_event_t *ev);
void ngx_pgcopy_empty_callback(ngx_http_request_t *r);
/*
 *    <empty_handler_to_avoid_core_dump>
 *    </defenition>
 */

static ngx_command_t  ngx_pgcopy_commands[] = {

    { ngx_string("pgcopy_server"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE23,
      ngx_http_conf_pgcopy_server,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pgcopy_query"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE3,
      ngx_http_conf_pgcopy_query,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pgcopy_delay"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_pgcopy_srv_conf_t, pgcopy_delay),
      NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_pgcopy_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_pgcopy_init,          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    ngx_http_pgcopy_srv_conf,      /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_pgcopy_loc_conf,      /* create location configuration */
    ngx_http_pgcopy_merge_loc_conf /* merge location configuration */
};

ngx_module_t ngx_http_pgcopy_module = {
    NGX_MODULE_V1,
    &ngx_pgcopy_module_ctx,        /* module context */
    ngx_pgcopy_commands,           /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 *    <utilit>
 */

/* <copy_from app="nginx" file="src/http/modules/ngx_http_auth_basic_module.c">
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */
static ngx_int_t
ngx_http_auth_basic_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    size_t   len;
    u_char  *basic, *p;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = ngx_pnalloc(r->pool, len);
    if (basic == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_HTTP_UNAUTHORIZED;
}
/* </copy_from> */

/*    </utilit>
 *    <configuration>
 */
static ngx_int_t
ngx_http_pgcopy_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt               *h_ap, *h_pap;
    ngx_http_core_main_conf_t         *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h_ap = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    h_pap = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);

    if (h_ap == NULL || h_pap == NULL) {
        return NGX_ERROR;
    }

    *h_ap = ngx_http_pgcopy_access_handler;
    *h_pap = ngx_http_pgcopy_init_access_handler;

    return NGX_OK;
}

void *
ngx_http_pgcopy_srv_conf(ngx_conf_t *cf)
{
    ngx_http_pgcopy_srv_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pgcopy_srv_conf_t));
    conf->pgcopy_delay = 3000;

    if (ngx_list_init(&conf->conn_info_list, cf->pool, 1, sizeof(connection_info_srv)) == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Can't init memory for connections list - ERROR!");
        return NGX_CONF_ERROR;
    }

    return conf;
}

void *
ngx_http_pgcopy_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pgcopy_loc_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pgcopy_loc_conf_t));
    return conf;
}

char *
ngx_http_conf_pgcopy_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                         *value = cf->args->elts;
    auth_enum_type                     auth_type = none;

    connection_info_srv               *conn_element;
    ngx_http_pgcopy_srv_conf_t        *pgscf = conf;

#define CAPTURE_LEN 2
    int                                captures[CAPTURE_LEN*3];
    ngx_regex_compile_t                rc;
    u_char                             errstr[255];

    if (value[1].len == 0 || value[2].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "PGCOPY: empty connection info in \"%V\" directive",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 4) {
        if (!ngx_strncasecmp((u_char*)"basic", value[3].data, value[3].len)) {
            auth_type = basic;            
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Authentification not recognized: \"%s\" - ERROR!", value[3].data);
            return NGX_CONF_ERROR;
        }
    }

    conn_element = ngx_list_push(&pgscf->conn_info_list);

    conn_element->conn_name.data = ngx_pstrdup(cf->pool, &value[1]);
    conn_element->conn_name.len = value[1].len;
    conn_element->conn_info.data = ngx_pstrdup(cf->pool, &value[2]);
    conn_element->conn_info.len = value[2].len;
    conn_element->auth_type = auth_type;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    ngx_memzero(&captures, sizeof(ngx_int_t)*CAPTURE_LEN);

    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.pattern = (ngx_str_t)ngx_string("(?:host=([\\d\\w.\\-_]+(?:\\:[0-9]+)*))");
    rc.options = NGX_REGEX_CASELESS;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "PGCOPY: regex compile ERROR!");
        return NGX_CONF_ERROR;
    }

    if (ngx_regex_exec(rc.regex, &conn_element->conn_info, (int*)captures, 3*CAPTURE_LEN) > NGX_REGEX_NO_MATCHED) {
        conn_element->conn_host.len = captures[3] - captures[2];
        conn_element->conn_host.data = conn_element->conn_info.data + captures[2];
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "PGCOPY: not found hostname in \"%V\" !", &cmd->name);
        return NGX_CONF_ERROR;
    }
#undef CAPTURE_LEN

#ifdef PGCOPY_DEBUG
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "<pgcopy_server connection_name=\"%V\">", &conn_element->conn_name);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "    Host addr      : \"%V\"", &conn_element->conn_host);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "    Connection info: \"%V\"", &conn_element->conn_info);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "    Auth type str  : \"%V\"", &value[3]);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "    Auth type enum : \"%i\"", conn_element->auth_type);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "</pgcopy_server>");
#endif

    return NGX_CONF_OK;
}

char *
ngx_http_conf_pgcopy_query(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    ngx_http_pgcopy_loc_conf_t        *pglcf = conf;
    ngx_str_t                         *value = cf->args->elts;

    ngx_http_pgcopy_srv_conf_t        *pgscf;
    ngx_uint_t                         i0;
    ngx_list_part_t                   *cilp;
    connection_info_srv               *srv_conf_conn_element;

    connection_info_loc               *current_conn_element;

    if (!ngx_strncasecmp((u_char*)"PUT", value[1].data, value[1].len)) {
        current_conn_element = &pglcf->PUT;
    } else if (!ngx_strncasecmp((u_char*)"POST", value[1].data, value[1].len)) {
        current_conn_element = &pglcf->POST;
    } else {
        current_conn_element = &pglcf->GET;
    }

    if (value[2].len == 0 || value[3].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                           "pgcopy: empty connection info in \"%V\" directive",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    pgscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_pgcopy_module);
    cilp = &pgscf->conn_info_list.part;
    srv_conf_conn_element = cilp->elts;

    for (i0 = 0 ;;i0++) {
        if (i0 >= cilp->nelts) {
            if (cilp->next == NULL) {
                break;
            }

            cilp = cilp->next;
            srv_conf_conn_element = cilp->elts;
            i0 = 0;
        }

        if (!ngx_strncasecmp(value[2].data, srv_conf_conn_element->conn_name.data, value[2].len)) {
            current_conn_element->conn_inf_srv = srv_conf_conn_element;
            break;
        }

    }

    if (!current_conn_element->conn_inf_srv) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                           "pgcopy: DB name does not found! \"%V\"",
                           &cmd->name);
        return NGX_CONF_ERROR;        
    }

    current_conn_element->pgquery.data = ngx_pstrdup(cf->pool, &value[3]);
    current_conn_element->pgquery.len = value[3].len;

    ngx_memzero(&current_conn_element->ns_compile, sizeof(ngx_http_script_compile_t));

    current_conn_element->ns_compile.variables = ngx_http_script_variables_count(&current_conn_element->pgquery);
    if (current_conn_element->ns_compile.variables > 0) {
        current_conn_element->ns_compile.cf = cf;
        current_conn_element->ns_compile.source = &current_conn_element->pgquery;
        current_conn_element->ns_lengths = NULL;
        current_conn_element->ns_compile.lengths = &current_conn_element->ns_lengths;
        current_conn_element->ns_values = NULL;
        current_conn_element->ns_compile.values = &current_conn_element->ns_values;
        current_conn_element->ns_compile.complete_lengths = 1;
        current_conn_element->ns_compile.complete_values = 1;

        if (ngx_http_script_compile(&current_conn_element->ns_compile) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

#ifdef PGCOPY_DEBUG
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "<pgcopy_query>");
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "    Conn_name      : \"%V\"", &current_conn_element->conn_inf_srv->conn_name);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "    Conn_info      : \"%V\"", &current_conn_element->conn_inf_srv->conn_info);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "    Conn_authon.   : \"%i\"", current_conn_element->conn_inf_srv->auth_type);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "    Conn_query     : \"%V\"", &current_conn_element->pgquery);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "    Nginx_script   : \"%i\"", current_conn_element->ns_compile.variables);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "</pgcopy_query>");
#endif

    pglcf->set_access_handler = 1;

    return NGX_CONF_OK;
}

char *
ngx_http_pgcopy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}

/*
 *    </configuration>
 *
 *    <handlers>
 */
static ngx_int_t 
ngx_http_pgcopy_init_access_handler(ngx_http_request_t *r)
{
    ngx_http_pgcopy_loc_conf_t        *pglcf;
    connection_info_loc               *current_loc_conninfo;
    u_char                            *full_conn_info;
    ngx_http_core_loc_conf_t          *clcf;
    ngx_http_pgcopy_ctx_t             *ctx;
    ngx_int_t                          len;

    ngx_str_t                          sc_pquery;

    pglcf = ngx_http_get_module_loc_conf(r, ngx_http_pgcopy_module);

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_http_pgcopy_init_access_handler>");

    if(!pglcf->set_access_handler) {
        return NGX_DECLINED;
    }

    switch(r->method) 
    {
        case NGX_HTTP_PUT:
            current_loc_conninfo = &pglcf->PUT;
            break;
        case NGX_HTTP_POST:
            current_loc_conninfo = &pglcf->POST;
            break;
        case NGX_HTTP_GET:
            current_loc_conninfo = &pglcf->GET;
            break;
        default:
            return NGX_DECLINED;
    }

    if(!current_loc_conninfo) {
        return NGX_DECLINED;
    }

    if(current_loc_conninfo->conn_inf_srv->auth_type) {
        ngx_http_auth_basic_user(r);
        if( r->headers_in.user.len && r->headers_in.passwd.len ) {    
            len  = current_loc_conninfo->conn_inf_srv->conn_info.len+
                   r->headers_in.user.len+r->headers_in.passwd.len+
                   sizeof(" user= password= sslmode=disable");

            full_conn_info = ngx_pcalloc(r->pool, len + 1);

            ngx_snprintf(full_conn_info, len,
                         "%V user=%V password=%V sslmode=disable",
                         &current_loc_conninfo->conn_inf_srv->conn_info,
                         &r->headers_in.user,
                         &r->headers_in.passwd);

        } else {
            return ngx_http_auth_basic_set_realm(r, &(ngx_str_t)ngx_string("Unauthorised request"));
        }
    } else {
        full_conn_info = ngx_pcalloc(r->pool, current_loc_conninfo->conn_inf_srv->conn_info.len+1);
        ngx_cpystrn(full_conn_info, 
                    current_loc_conninfo->conn_inf_srv->conn_info.data,
                    current_loc_conninfo->conn_inf_srv->conn_info.len+1);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, r->connection->log, 0, "PGCOPY: <info full_conn_info=\"%s\"/>", (char*)full_conn_info);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_pgcopy_ctx_t));
    ctx->full_conn_info = full_conn_info;

    ctx->sleep.data = r;
    ctx->sleep.log = r->connection->log;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ctx->client_body_buffer_size = clcf->client_body_buffer_size;

    if (current_loc_conninfo->ns_compile.variables > 0) {
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: <script_run>");
        if (ngx_http_script_run(r, &sc_pquery, current_loc_conninfo->ns_lengths->elts, 0, current_loc_conninfo->ns_values->elts) == NULL) {
            return NGX_ERROR;
        }

        ctx->pgquery = ngx_pcalloc(r->pool, sc_pquery.len+1);
        ngx_cpystrn(ctx->pgquery, sc_pquery.data, sc_pquery.len);
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: </script_run>");
    } else {
        ctx->pgquery = ngx_pcalloc(r->pool, current_loc_conninfo->pgquery.len+1);
        ngx_cpystrn(ctx->pgquery, 
                    current_loc_conninfo->pgquery.data,
                    current_loc_conninfo->pgquery.len);
    }

    ctx->current_loc_conninfo = current_loc_conninfo;
    ngx_http_set_ctx(r, ctx, ngx_http_pgcopy_module);

    ngx_pgcopy_upstream_init(r, ctx);
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_http_pgcopy_init_access_handler>");
    return NGX_OK;
}

ngx_int_t
ngx_pgcopy_start_pooling(ngx_http_request_t *r)
{
    ngx_http_pgcopy_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pgcopy_module);
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_start_pooling>");

    ctx->status = PQconnectPoll(ctx->pgconn);
    switch (ctx->status) 
    {
        case PGRES_POLLING_FAILED:
            PGCOPY_DTRACE1(r->connection->log, "PGCOPY PGRES_POLLING_FAILED! Process connect %s", PQresStatus(ctx->status));
            if (ngx_strncasecmp((u_char*)"FATAL:  password authentication failed", (u_char*)PQerrorMessage(ctx->pgconn), sizeof("FATAL:  password authentication failed"))){
                PGCOPY_DTRACE(r->connection->log, "PGCOPY password authentication failed!");
                if (ctx->current_loc_conninfo->conn_inf_srv->auth_type) {
                    ngx_http_finalize_request(r, ngx_http_auth_basic_set_realm(r, &(ngx_str_t)ngx_string("Unauthorised request")));
                } else {
                    ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
                }
            }
            PQfinish(ctx->pgconn);
            return NGX_ERROR;
        case PGRES_POLLING_OK:
            PGCOPY_DTRACE1(r->connection->log, "PGCOPY: <process connect='PGRES_POLLING_OK %s/>", PQresStatus(ctx->status));
            break;
        default:
            PGCOPY_DTRACE1(r->connection->log, "PGCOPY: <process connect='default %s'/>", PQresStatus(ctx->status));
            PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_start_pooling>");
            return NGX_AGAIN;
    }

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_start_pooling>");
    ctx->pg_stage = ngx_pgcopy_need_made;
    return ngx_pgcopy_need_made(r);
}

ngx_int_t
ngx_pgcopy_need_made(ngx_http_request_t *r)
{
    ngx_http_pgcopy_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pgcopy_module);
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_need_made>");

    switch(PQstatus(ctx->pgconn))
    {
        case CONNECTION_BAD:
            PGCOPY_DTRACE(r->connection->log, "PGCOPY: <connection status=\"BAD\"/>");
            return NGX_ERROR;
        case CONNECTION_STARTED:
        case CONNECTION_MADE:
            PGCOPY_DTRACE(r->connection->log, "PGCOPY: <connect_stage status=\"connected, need made or waiting to send...add timer\"");
            PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_need_made>");
            return NGX_AGAIN;
        default:
            PGCOPY_DTRACE(r->connection->log, "PGCOPY: <connecting status=\"DEFENED\"/>");
    }

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_need_made>");
    return NGX_OK;
}

static ngx_int_t 
ngx_http_pgcopy_access_handler(ngx_http_request_t *r)
{
    ngx_http_pgcopy_ctx_t   *ctx;
    ngx_int_t                rc;
    ngx_http_pgcopy_loc_conf_t        *pglcf;

    pglcf = ngx_http_get_module_loc_conf(r, ngx_http_pgcopy_module);
    if(!pglcf->set_access_handler) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pgcopy_module);
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_http_pgcopy_access_handler>");

    rc = ctx->pg_stage(r);

    switch(rc) {
        case NGX_OK:
            r->state = 0;
            r->content_handler = ngx_pgcopy_content_handler;
            break;
        case NGX_AGAIN:
            r->phase_handler--;
            break;
        default:
            PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_http_pgcopy_access_handler>");
            return rc;
    }

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_http_pgcopy_access_handler>");
    return NGX_OK;  
}

ngx_int_t
ngx_pgcopy_content_handler(ngx_http_request_t *r)
{
    ngx_http_pgcopy_ctx_t     *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_pgcopy_module);
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_content_handler>");

    if (ngx_pgcopy_upstream_test_connect(ctx->upstream->peer.connection) != NGX_OK) {
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: <error return_from=\"ngx_pgcopy_upstream_test_connect\" action=\"break_thread;break_pearent_func\"/>");
        return NGX_ERROR;
    }
    PGCOPY_DTRACE1(r->connection->log, "PGCOPY: <begin_out_query/>\n<query>\n%s\n</query>", ctx->pgquery);
    PQsendQuery(ctx->pgconn, (const char *)ctx->pgquery);

    rUPSTREAM_RW_HANDLER(r, ngx_pgcopy_query_arbiter);
    ngx_add_timer(ctx->pc->connection->write, 100);

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_content_handler>");
    return NGX_OK;
}
/*
 *    </handlers>
 *
 *    <upstream>
 */

ngx_int_t
ngx_pgcopy_upstream_init(ngx_http_request_t *r, ngx_http_pgcopy_ctx_t *ctx)
{
    ngx_http_upstream_t               *u;
    ngx_http_upstream_srv_conf_t      *uscf;

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_upstream_init>");

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body_in_clean_file = 1;
    r->request_body_file_group_access = 1;

    u = r->upstream;

    u->schema.len = sizeof("postgres://") - 1;
    u->schema.data = (u_char *) "postgres://";

    u->output.tag = (ngx_buf_tag_t) &ngx_http_pgcopy_module;//wtf??
 
    u->conf = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_conf_t));
    u->conf->upstream = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_srv_conf_t));
    uscf = u->conf->upstream;
    uscf->peer.init = ngx_pgcopy_upstream_init_peer;

    u->create_request = ngx_pgcopy_create_request;
    u->reinit_request = ngx_pgcopy_reinit_request;
    u->process_header = ngx_pgcopy_process_header;
    u->abort_request = ngx_http_pgcopy_abort_request;
    u->finalize_request = ngx_pgcopy_finalize_request;

    //ngx_postgres_loc_conf_t* -> ngx_http_upstream_conf_t            upstream
    //conf->upstream.connect_timeout = 2000;
    
    //u->conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    u->conf->connect_timeout = 5000;
    u->conf->read_timeout = 5000;
    u->conf->timeout=5000;
    u->conf->next_upstream_timeout=1000;
    u->conf->next_upstream_tries=4;
    u->conf->buffering = 0; //0
    u->conf->ignore_client_abort = 1; //1
    //u->conf->send_lowat = 0;
    u->conf->bufs.num = 3;
    u->conf->busy_buffers_size = 512;
    u->conf->max_temp_file_size = 4096;
    //u->conf->intercept_errors = 1;
    //u->conf->intercept_404 = 1;
    //u->conf->pass_request_headers = 1;
    u->conf->pass_request_body = 1;

    r->state = 0;
    u->peer.get = ngx_pgcopy_upstream_get_peer_begin_connect;
    u->peer.data = r;
    u->peer.tries=10;

    u->read_event_handler = ngx_pgcopy_query_arbiter;
    u->write_event_handler = ngx_pgcopy_query_arbiter;
    
    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    u->pipe->input_ctx = r;
    u->accel = 1;

    ctx->upstream = u;
    ctx->n=0;
/*
    rUPSTREAM_RW_HANDLER(r, ngx_pgcopy_query_arbiter);
    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init); //for GET NEED SET CONTECST HANDLER ????
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_upstream_init abort info=\"special responce\">");
        return rc;
    }
//*/

    ngx_http_upstream_init(r);

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_upstream_init>");

    return NGX_OK;
}

/*
 * <copy_from module="ngx_postgres"  file="ngx_postgres_util.c" function="ngx_postgres_upstream_test_connect">
 * Copyright (C) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
 * Copyright (C) 2009-2010, Xiaozhe Wang <chaoslawful@gmail.com>
 * Copyright (C) 2009-2010, Yichun Zhang <agentzh@gmail.com>
 */

ngx_int_t
ngx_pgcopy_upstream_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)
    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, c->write->kq_errno, "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
            err = ngx_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}
/* 
 * </copy_from>
 */
ngx_int_t
ngx_pgcopy_upstream_get_peer_begin_connect(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_pgcopy_ctx_t *ctx;
    ngx_http_request_t    *r = pc->data;

    ngx_int_t              fd;
    ngx_connection_t      *pgxc = NULL;

    struct sockaddr_in *serv_addr;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pgcopy_module);
    PGCOPY_DTRACE(pc->log, "PGCOPY: <ngx_pgcopy_upstream_get_peer_begin_connect>");

    ctx->pgconn = PQconnectStart((const char *)ctx->full_conn_info);
    PQsetnonblocking(ctx->pgconn, 1);

    fd = PQsocket(ctx->pgconn);
    if (!fd) {
        ngx_log_debug(NGX_LOG_DEBUG_EVENT, pc->log, 0, "PGCOPY: PQsocket is null!!!!");        
    }

    pc->name = &ctx->current_loc_conninfo->conn_inf_srv->conn_host;

    //http://lxr.nginx.org/source/src/core/ngx_inet.c#0507
    serv_addr = ngx_pcalloc(r->pool, sizeof(struct sockaddr_in));
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr->sin_port = htons((in_port_t)5432); //u_char *p;size_t plen; port = ngx_atoi(p, plen);
    pc->sockaddr = (struct sockaddr *)serv_addr;
    pc->socklen = sizeof(struct sockaddr_in);

    pc->cached = 0;

    pgxc = pc->connection =  ngx_get_connection(fd, r->connection->log);
    if (pgxc == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PGCOPY: failed to get a free nginx connection");
    }
    pc->connection->log = r->connection->log;
    pc->connection->log_error = NGX_ERROR_ERR;
    pc->connection->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    pc->connection->data = r;

    pc->connection->read->log = r->connection->log;
    pc->connection->write->log = r->connection->log;

    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(pgxc) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PGCOPY: failed to set EVENT");
            return NGX_ERROR;
        }

    } else if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        if ((ngx_add_event(pc->connection->read, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK)
            | (ngx_add_event(pc->connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PGCOPY: failed to set EVENT");
            return NGX_ERROR;
        }
    } else {
        if ((ngx_add_event(pc->connection->read, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK)
            | (ngx_add_event(pc->connection->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT) != NGX_OK)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PGCOPY: failed to set EVENT");
            return NGX_ERROR;
        }
    }

    ctx->pc = pc;
    r->main->count++;

    //<empty_handlers_values> <!--add to avoid core dump in access to empty values-->
    pc->connection->read->data=r;
    pc->connection->read->handler = ngx_pgcopy_empty_handler;
    pc->connection->write->data=r;
    pc->connection->write->handler = ngx_pgcopy_empty_handler;
    //</empty_handlers_values>

    pc->connection->sockaddr = pc->sockaddr;
    pc->connection->socklen = pc->socklen;

    ctx->pg_stage = ngx_pgcopy_start_pooling;
    //ngx_pgcopy_start_pooling(r);

    PGCOPY_DTRACE(pc->log, "PGCOPY: </ngx_pgcopy_upstream_get_peer_begin_connect>");
    return NGX_OK;
}

/* 
 * <read_write_event_handler STAGES>
 */

void
ngx_pgcopy_query_arbiter(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    PGresult                  *res;
    ngx_http_pgcopy_ctx_t     *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pgcopy_module);
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_query_arbiter>");

    res = PQgetResult(ctx->pgconn);

    if (PQisBusy(ctx->pgconn)) {
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: <busy action=\"add_timer\"/>");
        if( !ctx->pc->connection->write->timer_set ) {
            ngx_add_timer(ctx->pc->connection->write, 100);
        }
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_query_arbiter>");
        return;
    }

    if (PQresultStatus(res) == PGRES_COPY_OUT) {
        ctx->cl = ngx_alloc_chain_link(r->pool);

        rUPSTREAM_RW_HANDLER(r, ngx_pgcopy_out);

        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = -1; //Transfer-Encoding: chunked
        ngx_http_send_header(r);
        r->header_sent = 1;

        ctx->cl->buf = ngx_create_temp_buf(r->pool, ctx->client_body_buffer_size);
        ctx->cl->buf->memory = 1;
        ctx->cl->buf->tag = (ngx_buf_tag_t) &ngx_http_pgcopy_module;;
        ctx->cl->next = NULL;

        ctx->n = 0;

        ngx_pgcopy_out(r, u);

    }
    else if (PQresultStatus(res) == PGRES_COPY_IN) //may be use PGASYNC_COPY_IN
    {
        ngx_http_read_client_request_body(r, ngx_pgcopy_empty_callback);

        if (r->request_body->temp_file) {
            ctx->current_buffer = ngx_pcalloc(r->pool, ctx->client_body_buffer_size);
        } else {
            ctx->cl = r->request_body->bufs;
        }

        rUPSTREAM_RW_HANDLER(r, ngx_pgcopy_in);
        ngx_pgcopy_in(r, u);
    }
    else if (PQresultStatus(res) == PGRES_FATAL_ERROR) {
            PGCOPY_DTRACE(r->connection->log, "PGCOPY: <PGRES_FATAL_ERROR/>");
            //ngx_pgcopy_finalize_request(r, NGX_ERROR);
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
    } else {
        PGCOPY_DTRACE1(r->connection->log, "PGCOPY: <EXIT CODE PGRES_COMMAND_OKif=2 %i/>", PQresultStatus(res));
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: <busy action=\"add_timer\"/>");
        if( !ctx->pc->connection->write->timer_set ) {
            ngx_add_timer(ctx->pc->connection->write, 100);
        }
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_query_arbiter>");
        return;
    }

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_query_arbiter>");
}

void
ngx_pgcopy_in(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    PGresult                *res;
    ngx_http_pgcopy_ctx_t   *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_pgcopy_module);

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_in>");

    if (PQisBusy(ctx->pgconn)) {
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: <busy action=\"add_timer\"/>");
        if( !ctx->pc->connection->write->timer_set ) ngx_add_timer(ctx->pc->connection->write, 100);
        return;
    }

    if (r->request_body->temp_file) {
        ctx->n = ngx_read_file(&r->request_body->temp_file->file, ctx->current_buffer, ctx->client_body_buffer_size, ctx->offset);
        ctx->offset += ctx->n;
    } else if (ctx->cl){
        ctx->n = ctx->cl->buf->last - ctx->cl->buf->pos;
        ctx->current_buffer = ctx->cl->buf->pos;

        if(!ctx->cl->buf->last_buf && ctx->cl->next) {
            ctx->cl = ctx->cl->next;
        } else {
            ctx->cl = 0;
        }
    } else {
        ctx->n = 0;
    }

    if (ctx->n > 0){
        PGCOPY_DTRACE2(r->connection->log, "PGCOPY: <begin_data_output/>\n<data size=\"%i\">\n%s\n</data>", ctx->n, ctx->current_buffer);

        if( PQputCopyData(ctx->pgconn, (const char *)ctx->current_buffer, ctx->n ) < 0 ) {
            ngx_log_debug0(NGX_LOG_WARN, r->connection->log, 0, "PGCOPY: PQputCopyData ERROR!!");
        }
    }

    if (r->request_body->rest || (ctx->n > 0) ) {
        if (!ctx->pc->connection->write->timer_set) {
            ngx_add_timer(ctx->pc->connection->write, 100);
        }
    } else { 

        PQputCopyEnd(ctx->pgconn, NULL);
        res = PQgetResult(ctx->pgconn);
        if (PQresultStatus(res) != PGRES_COMMAND_OK)
        {
            PGCOPY_DTRACE(r->connection->log, "PGCOPY: <PQputCopyData ERROR/>");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        } else {
            ngx_http_finalize_request(r, NGX_HTTP_CREATED);
        }

        ngx_http_finalize_request(r, NGX_OK);//drop keep state
        return;
    }

    if (!PQconsumeInput(ctx->pgconn) || (PQtransactionStatus(ctx->pgconn) == PQTRANS_INERROR)){
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: <PQputCopyData ERROR/>");
        PQputCopyEnd(ctx->pgconn, NULL);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        ngx_http_finalize_request(r, NGX_OK);//drop keep state
    }

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_in>");
}

void
ngx_pgcopy_out(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_http_pgcopy_ctx_t   *ctx;
    u_char                  *buff_last_next = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pgcopy_module);
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_out>");

    if (PQisBusy(ctx->pgconn) | !PQconsumeInput(ctx->pgconn)) {
        PGCOPY_DTRACE(r->connection->log, "PGCOPY: <busy action=\"add_timer\"/>");
        if( !ctx->pc->connection->read->timer_set ) ngx_add_timer(ctx->pc->connection->read, 100);//timeout
        return;
    }

    ctx->cl->buf->last = ctx->cl->buf->start;
    ctx->cl->buf->pos = ctx->cl->buf->start;
    ctx->cl->buf->recycled = 1;
    ngx_memzero(ctx->cl->buf->start, ctx->client_body_buffer_size);

    do {
        if (ctx->n == 0) {
            ctx->n = PQgetCopyData(ctx->pgconn, (char**)&ctx->current_buffer, 1);//async for true
        }

        if (ctx->n < 0) {
            PGCOPY_DTRACE(r->connection->log, "PGCOPY: ctx->n -1 !!!!!!!");
            break;
        } else if (ctx->n > 0) {
            buff_last_next = ctx->cl->buf->last + ctx->n;
            if (ctx->cl->buf->end < buff_last_next) {
                if (!ctx->pc->connection->read->timer_set) {
                    ngx_add_timer(ctx->pc->connection->read, 100);
                }
                break;
            }

            ctx->cl->buf->last = ngx_copy(ctx->cl->buf->last, ctx->current_buffer, ctx->n);
            ctx->cl->buf->last = buff_last_next;
            ctx->n = 0;

            PQfreemem(ctx->current_buffer);
        } else {
            break;
        }
    } 
    while (ctx->cl->buf->end > buff_last_next);

    if ((ctx->cl->buf->last != ctx->cl->buf->start) || ctx->n < 0) {
        PGCOPY_DTRACE1(r->connection->log, "PGCOPY: <data>\n%s</data>", ctx->cl->buf->start);

        if (ctx->n < 0) {
            ctx->cl->buf->last_buf = 1;
            ctx->cl->buf->last_in_chain = 1;
            ngx_http_output_filter(r, ctx->cl);
            ngx_http_finalize_request(r, NGX_OK);
        } else {
            ngx_http_output_filter(r, ctx->cl);
        }
    }

    if (ctx->n > -1 && !ctx->pc->connection->read->timer_set) {
        ngx_add_timer(ctx->pc->connection->read, 100);
    }

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_out>");
}

/* 
 *</read_write_event_handler STAGES>
 */

void
ngx_pgcopy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{

    ngx_http_pgcopy_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_pgcopy_module);

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_finalize_request>");

    ctx->pgres = PQgetResult(ctx->pgconn);
    if (PQresultStatus(ctx->pgres) == PGRES_FATAL_ERROR) {
            ngx_log_debug1(NGX_LOG_WARN, r->connection->log, 0, "PGCOPY: PQgetResult ERROR status: %s\n", PQresultErrorMessage(ctx->pgres) );
    }
    PQfinish(ctx->pgconn);

    if (ctx->pc->connection->write->timer_set) ngx_del_timer(ctx->pc->connection->write);
    if (ctx->pc->connection->read->timer_set) ngx_del_timer(ctx->pc->connection->read);

    r->main->count--;

    //ngx_free_connection(ctx->pc->connection);
    //ngx_http_cleanup_add(r, 0);
    //ngx_free_connection(r->connection);

    PGCOPY_DTRACE(r->connection->log, "PGCOPY: </ngx_pgcopy_finalize_request>");
    return;

}
/*
 *    </upstream>
 *
 *    <empty_handler_to_avoid_core_dump>
 */

ngx_int_t
ngx_pgcopy_reinit_request(ngx_http_request_t *r)
{
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_reinit_request/>");
    return NGX_OK;
}

ngx_int_t
ngx_pgcopy_create_request(ngx_http_request_t *r) 
{
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_create_request/>");
    return NGX_OK;
}

ngx_int_t
ngx_pgcopy_upstream_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf)
{
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_upstream_init_peer/>");
    return NGX_OK;
}

void
ngx_http_pgcopy_abort_request(ngx_http_request_t *r)
{
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_http_pgcopy_abort_request/>");
}

ngx_int_t
ngx_pgcopy_process_header(ngx_http_request_t *r) 
{
    PGCOPY_DTRACE(r->connection->log, "PGCOPY: <ngx_pgcopy_process_header/>");
    return NGX_OK;
}

void
ngx_pgcopy_empty_handler(ngx_event_t *ev)
{
    return;
}

void
ngx_pgcopy_empty_callback(ngx_http_request_t *r)
{
    return;
}

/*
 *    </empty_handler_to_avoid_core_dump>
 */
