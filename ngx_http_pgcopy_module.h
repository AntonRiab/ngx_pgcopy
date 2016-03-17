/*
 * Copyright (C) Anton Riabchevskiy (AntonRiab)
 * All rights reserved.
 */

#ifndef PGCOPY_H
#define PGCOPY_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <libpq-fe.h>

#ifdef PGCOPY_DEBUG
    #define PGCOPY_DTRACE(log, message)          ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0, message);
    #define PGCOPY_DTRACE1(log, message, p0)     ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0, message, p0);
    #define PGCOPY_DTRACE2(log, message, p0, p1) ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0, message, p0, p1);
#else
    #define PGCOPY_DTRACE(log, message)          /*Must be debug output*/
    #define PGCOPY_DTRACE1(log, message, p0)     /*Must be debug output*/
    #define PGCOPY_DTRACE2(log, message, p0, p1) /*Must be debug output*/
#endif

#define rUPSTREAM_RW_HANDLER(r, func) \
        r->upstream->read_event_handler = func ;\
        r->upstream->write_event_handler = func ;

extern ngx_module_t  ngx_http_pgcopy_module;

typedef enum {
    none,
    basic
} auth_enum_type;

typedef struct {
    ngx_msec_t                 pgcopy_delay;
    ngx_list_t                 conn_info_list;
} ngx_http_pgcopy_srv_conf_t;

typedef struct {
    ngx_str_t                  conn_name;
    ngx_str_t                  conn_info;
    ngx_str_t                  conn_host;
    auth_enum_type             auth_type;
} connection_info_srv;

typedef struct {
    connection_info_srv       *conn_inf_srv;
    ngx_str_t                  pgquery;

    ngx_http_script_compile_t  ns_compile;
    ngx_array_t               *ns_lengths;
    ngx_array_t               *ns_values;
} connection_info_loc;

typedef struct {
    connection_info_loc        PUT;
    connection_info_loc        POST;
    connection_info_loc        GET;
    ngx_int_t                  set_access_handler;
    ngx_int_t                  set_content_handler;
    ngx_int_t                  test;
} ngx_http_pgcopy_loc_conf_t;

typedef struct {
    u_char                    *full_conn_info;
    u_char                    *pgquery;
    PGconn                    *pgconn;
    size_t                     client_body_buffer_size;

    connection_info_loc       *current_loc_conninfo;

    PostgresPollingStatusType  status;
    PGresult                  *pgres;
    ngx_int_t                  pgstage_connect;
    ngx_msec_t                 pgcopy_delay; 

    ngx_event_t                sleep;
    ngx_chain_t               *cl;

    u_char                    *current_buffer;
    off_t                      offset;
    ngx_int_t                  n;

    ngx_http_upstream_t       *upstream;
    ngx_peer_connection_t     *pc;
} ngx_http_pgcopy_ctx_t;

#endif
