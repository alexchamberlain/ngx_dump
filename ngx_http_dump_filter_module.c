
#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <nginx.h>

#include "dump_string_maps.h"

/* The public face of ngx_dump */
ngx_module_t ngx_http_dump_filter_module;
static ngx_http_module_t ngx_http_dump_filter_module_ctx;
static ngx_command_t ngx_http_dump_filter_commands[];

/* Configuration */
static ngx_int_t ngx_http_dump_filter_init(ngx_conf_t *);
static void * ngx_http_dump_filter_create_loc_conf(ngx_conf_t *);
static char * ngx_http_dump_filter_merge_loc_conf(ngx_conf_t *, void *, void *);
static char * ngx_http_dump(ngx_conf_t *, ngx_command_t *, void *);

static ngx_http_output_header_filter_pt ngx_http_dump_next_header_filter;
static ngx_http_output_body_filter_pt   ngx_http_dump_next_body_filter;

/* Filters */
static ngx_int_t ngx_http_dump_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_dump_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

/* The public face of ngx_dns */
ngx_module_t ngx_http_dump_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_dump_filter_module_ctx,      /* module context */
    ngx_http_dump_filter_commands,         /* module directives */
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

static ngx_http_module_t ngx_http_dump_filter_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_dump_filter_init,     /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_dump_filter_create_loc_conf, /* create location configuration */
    ngx_http_dump_filter_merge_loc_conf   /* merge location configuration */
};

static ngx_command_t ngx_http_dump_filter_commands[] = {
  {
    ngx_string("dump"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_dump,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  ngx_null_command
};

/* Configuration */
typedef struct {
  ngx_flag_t binary;
} ngx_http_dump_filter_loc_conf_t;

static ngx_int_t ngx_http_dump_filter_init(ngx_conf_t * cf) {
  ngx_http_dump_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter       = ngx_http_dump_header_filter;

  ngx_http_dump_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter       = ngx_http_dump_body_filter;

  return NGX_OK;
}

static void * ngx_http_dump_filter_create_loc_conf(ngx_conf_t * cf) {
  ngx_http_dump_filter_loc_conf_t *conf;
  
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dump_filter_loc_conf_t));
  if(conf == NULL) {
    return NGX_CONF_ERROR;
  }

  conf->binary = NGX_CONF_UNSET;

  return conf;
}

static char * ngx_http_dump_filter_merge_loc_conf(ngx_conf_t * cf, void * parent, void * child) {
  ngx_http_dump_filter_loc_conf_t *prev = parent;
  ngx_http_dump_filter_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->binary, prev->binary, 0);

  return NGX_CONF_OK;
}

static char * ngx_http_dump(ngx_conf_t * cf, ngx_command_t *cmd, void * conf) {
  ngx_http_dump_filter_loc_conf_t * dump_loc_cf = conf;
  ngx_str_t * value = cf->args->elts;
  //ngx_int_t   vn    = cf->args->nelts;
  ngx_str_t   binary = ngx_string("binary");

  if(value[1].len == binary.len && ngx_strncmp(value[1].data, binary.data, binary.len) == 0) {
    dump_loc_cf->binary = 1;
  }

  return NGX_CONF_OK;
}

/* Filters */
typedef struct {
  ngx_flag_t headers_sent;
} ngx_dump_filter_ctx_t;

static ngx_int_t ngx_http_dump_header_filter(ngx_http_request_t *r) {
  ngx_dump_filter_ctx_t           * ctx;
  ngx_http_dump_filter_loc_conf_t * dump_loc_cf;

  dump_loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_dump_filter_module);

  if(!dump_loc_cf->binary) {
    return ngx_http_dump_next_header_filter(r);
  }

  ctx = ngx_pcalloc(r->pool, sizeof(ngx_dump_filter_ctx_t));
  if(ctx == NULL) {
    return NGX_ERROR;
  }

  /* set by ngx_pcalloc
   * 
   * ctx->headers_sent = 0;
   */

  ngx_http_set_ctx(r, ctx, ngx_http_dump_filter_module);
  ngx_http_clear_content_length(r);

  return ngx_http_dump_next_header_filter(r);
}

static ngx_int_t ngx_http_dump_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
  ngx_dump_filter_ctx_t           * ctx;
  ngx_http_dump_filter_loc_conf_t * dump_loc_cf;
  ngx_chain_t                     * cl; /* Input chain iterator */
  ngx_chain_t                     * nl = NULL; /* Output chain iterator */

  ngx_int_t rc = NGX_OK;

  if(in == NULL || r->header_only) {
    return ngx_http_dump_next_body_filter(r, in);
  }

  dump_loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_dump_filter_module);

  if(!dump_loc_cf->binary) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Not dumping binary.");
    return ngx_http_dump_next_body_filter(r, in);
  }
  
  ctx = ngx_http_get_module_ctx(r, ngx_http_dump_filter_module);
  if(ctx == NULL) {
    return ngx_http_dump_next_body_filter(r, in);
  }

  //int base = 2;
  int base_log_2 = 1;
  int columns = 16;
  int bytes_on_line = (columns * base_log_2)/8;
  int line_length = 6 + 2 + columns + bytes_on_line + 2 + bytes_on_line + 1;

  for(cl = in; cl; cl = cl->next) {
    ngx_buf_t * cb = cl->buf;
    ngx_int_t   cbl = cb->last - cb->pos + 1;
    ngx_int_t i;

    if(nl == NULL) {
      nl = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
      if(nl == NULL) {
        return NGX_ERROR;
      }
    }

    if(nl->buf == NULL) {
      nl->buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
      if(nl->buf == NULL) {
        return NGX_ERROR;
      }
    }

    if(nl->buf->start == NULL) {
      ngx_int_t n = (cbl * line_length)/bytes_on_line;
      nl->buf->start = ngx_pcalloc(r->pool, n);
      if(nl->buf->start == NULL) {
        return NGX_ERROR;
      }
      nl->buf->end = nl->buf->start + n;
      nl->buf->pos = nl->buf->start;
      nl->buf->last = nl->buf->start - 1;
      nl->buf->memory = 1;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "start: %p; pos: %p; last: %p; end: %p;",
                  nl->buf->start, nl->buf->pos, nl->buf->last, nl->buf->end);

    // (cbl + bytes_on_line - 1) / bytes_on_line ~= cbl / bytes_on_line
    //   except that it rounds up rather than down.
    for(i = 0; i < (cbl + bytes_on_line - 1) / bytes_on_line; ++i) {
      nl->buf->pos += sprintf((char *) nl->buf->pos, "%.6x: ", i * bytes_on_line);
      nl->buf->pos += sprintf((char *) nl->buf->pos, "%s ", dump_binary_string_map[cl->buf->pos[i*bytes_on_line]]);
      nl->buf->pos += sprintf((char *) nl->buf->pos, "%s ", dump_binary_string_map[cl->buf->pos[i*bytes_on_line + 1]]);
      nl->buf->pos += sprintf((char *) nl->buf->pos, " %.2s\n", cl->buf->pos + i*bytes_on_line);
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "start: %p; pos: %p; last: %p; end: %p;",
		    nl->buf->start, nl->buf->pos, nl->buf->last, nl->buf->end);

      nl->buf->last = nl->buf->pos - 1;
    }
    nl->buf->pos  = nl->buf->start;

    nl->buf->last_buf = 1;
    nl->buf->last_in_chain = 1;
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "start: %p; pos: %p; last: %p; end: %p;",
                  nl->buf->start, nl->buf->pos, nl->buf->last, nl->buf->end);

    return ngx_http_dump_next_body_filter(r, nl);
  }

  return ngx_http_dump_next_body_filter(r, nl);
}
