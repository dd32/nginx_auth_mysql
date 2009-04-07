/*
 * Copyright (C) 2009 Automattic Inc.
 *
 * Based on nginx's basic auth module by Igor Sysoev and
 * nginx PAM auth module by  Sergio Talens-Oliag
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <mysql.h>

#include "crypt_private.h"

#define NGX_AUTH_MYSQL_MAX_QUERY_LEN 1000
#define NGX_AUTH_MYSQL_MAX_FIELD_LEN 256

/* Module context data */
typedef struct {
    ngx_str_t  passwd;
} ngx_http_auth_mysql_ctx_t;

/* userinfo */
typedef struct {
    ngx_str_t  username;
    ngx_str_t  password;
} ngx_auth_mysql_userinfo;

/* Module configuration struct */
typedef struct {
	ngx_str_t realm;
	ngx_str_t host;
	ngx_uint_t port;
	ngx_str_t user;
	ngx_str_t password;
	ngx_str_t database;
	ngx_str_t table;
	ngx_str_t user_column;
	ngx_str_t password_column;
	ngx_str_t encryption_type_str;
	ngx_uint_t encryption_type;
	ngx_str_t allowed_users;
} ngx_http_auth_mysql_loc_conf_t;

/* Encryption types */
typedef struct {
	ngx_str_t id;
	ngx_uint_t (*checker)(ngx_http_request_t *r, ngx_str_t sent_password, ngx_str_t actual_password);
} ngx_http_auth_mysql_enctype_t;

/* Module handler */
static ngx_int_t ngx_http_auth_mysql_handler(ngx_http_request_t *r);

/* Function that authenticates the user via MySQL */
static ngx_int_t ngx_http_auth_mysql_authenticate(ngx_http_request_t *r,
    ngx_http_auth_mysql_ctx_t *ctx, ngx_str_t *passwd, void *conf);

static ngx_uint_t ngx_http_auth_mysql_check_plain(ngx_http_request_t *r, ngx_str_t sent_password, ngx_str_t actual_password);

static ngx_uint_t ngx_http_auth_mysql_check_md5(ngx_http_request_t *r, ngx_str_t sent_password, ngx_str_t actual_password);

static ngx_uint_t ngx_http_auth_mysql_check_phpass(ngx_http_request_t *r, ngx_str_t sent_password, ngx_str_t actual_password);

static ngx_int_t ngx_http_auth_mysql_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);

static void *ngx_http_auth_mysql_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_auth_mysql_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_http_auth_mysql_init(ngx_conf_t *cf);

static char *ngx_http_auth_mysql(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_handler_pt  ngx_http_auth_mysql_p = ngx_http_auth_mysql;

static ngx_http_auth_mysql_enctype_t ngx_http_auth_mysql_enctypes[] = {
	{
		ngx_string("none"),
		ngx_http_auth_mysql_check_plain
	},
	{
		ngx_string("md5"),
		ngx_http_auth_mysql_check_md5
	},
	{
		ngx_string("phpass"),
		ngx_http_auth_mysql_check_phpass
	}
};

static ngx_command_t ngx_http_auth_mysql_commands[] = {
	{ ngx_string("auth_mysql_realm"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, realm),
	&ngx_http_auth_mysql_p },
		
	{ ngx_string("auth_mysql_host"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, host),
	NULL },
	
	{ ngx_string("auth_mysql_port"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_num_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, port),
	NULL },

	{ ngx_string("auth_mysql_database"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, database),
	NULL },
	
	{ ngx_string("auth_mysql_password"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, password),
	NULL },

	{ ngx_string("auth_mysql_table"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, table),
	NULL },
	
	{ ngx_string("auth_mysql_user"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, user),
	NULL },	
	
	{ ngx_string("auth_mysql_password"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, password),
	NULL },	
	
	{ ngx_string("auth_mysql_user_column"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, user_column),
	NULL },	
	
	{ ngx_string("auth_mysql_password_column"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, password_column),
	NULL },
	
	{ ngx_string("auth_mysql_encryption_type"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, encryption_type_str),
	NULL },
	
	{ ngx_string("auth_mysql_allowed_users"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_auth_mysql_loc_conf_t, allowed_users),
	NULL }
};


static ngx_http_module_t  ngx_http_auth_mysql_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_mysql_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_mysql_create_loc_conf,     /* create location configuration */
    ngx_http_auth_mysql_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_auth_mysql_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_mysql_module_ctx,         /* module context */
    ngx_http_auth_mysql_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_auth_mysql_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;
    ngx_http_auth_mysql_ctx_t  *ctx;
    ngx_http_auth_mysql_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_mysql_module);

    if (alcf->realm.len == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_mysql_module);

    if (ctx) {
        return ngx_http_auth_mysql_authenticate(r, ctx, &ctx->passwd, alcf);
    }

    /* Decode http auth user and passwd, leaving values on the request */
    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        return ngx_http_auth_mysql_set_realm(r, &alcf->realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check user & password using MySQL */
    return ngx_http_auth_mysql_authenticate(r, ctx, &ctx->passwd, alcf);
}

static ngx_int_t
ngx_http_auth_mysql_authenticate(ngx_http_request_t *r,
    ngx_http_auth_mysql_ctx_t *ctx, ngx_str_t *passwd, void *conf)
{
    ngx_http_auth_mysql_loc_conf_t  *alcf = conf;

    ngx_auth_mysql_userinfo  uinfo;

    size_t   len;
	ngx_int_t auth_res;
	ngx_int_t found_in_allowed;
	u_char  *uname_buf, *p, *next_username;
	ngx_str_t actual_password;

	u_char query_buf[NGX_AUTH_MYSQL_MAX_QUERY_LEN];	
	u_char esc_table[NGX_AUTH_MYSQL_MAX_FIELD_LEN];
	u_char esc_user[NGX_AUTH_MYSQL_MAX_FIELD_LEN];
	u_char esc_user_column[NGX_AUTH_MYSQL_MAX_FIELD_LEN];
	u_char esc_pass_column[NGX_AUTH_MYSQL_MAX_FIELD_LEN];

	MYSQL *conn, *mysql_result;
	MYSQL_RES *query_result;

    /**
     * Get username and password, note that r->headers_in.user contains the
     * string 'user:pass', so we need to copy the username
     **/
    for (len = 0; len < r->headers_in.user.len; len++) {
	if (r->headers_in.user.data[len] == ':') {
            break;
	}
    }
    uname_buf = ngx_palloc(r->pool, len+1);
    if (uname_buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    p = ngx_cpymem(uname_buf, r->headers_in.user.data , len);
    *p ='\0';

    uinfo.username.data = uname_buf;
    uinfo.username.len  = len;
    
    uinfo.password.data = r->headers_in.passwd.data;
    uinfo.password.len  = r->headers_in.passwd.len;

	/* Check if the user is among allowed users */
	if (ngx_strcmp(alcf->allowed_users.data, "") != 0) {
		found_in_allowed = 0;
		// strdup will allocate only len bytes, and we want one more for \0
		alcf->allowed_users.len++;
		char* allowed_users = (char*)ngx_pstrdup(r->pool, &alcf->allowed_users);
		alcf->allowed_users.len--;
		allowed_users[alcf->allowed_users.len] = '\0';
		
		while ((next_username = (u_char*)strsep(&allowed_users, " \t")) != NULL) {
			if (ngx_strcmp(next_username, uinfo.username.data) == 0) {
				found_in_allowed = 1;
				break;
			}
		}

		if (1 != found_in_allowed) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"auth_mysql: User '%s' isn't among allowed users.", (char*)uinfo.username.data);
			return ngx_http_auth_mysql_set_realm(r, &alcf->realm);
		}
	}

	conn = mysql_init(NULL);
	if (conn == NULL) {
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
		      "auth_mysql: Could not initialize MySQL connection");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	
	mysql_result = mysql_real_connect(conn, (char*)alcf->host.data, (char*)alcf->user.data, (char*)alcf->password.data,
			(char*)alcf->database.data, alcf->port, NULL, 0);			
	if (mysql_result == NULL) {
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
			"auth_mysql: Could not connect to MySQL server: %s", mysql_error(conn));
		mysql_close(conn);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	mysql_real_escape_string(conn, (char*)esc_pass_column, (char*)alcf->password_column.data, alcf->password_column.len);
	mysql_real_escape_string(conn, (char*)esc_table, (char*)alcf->table.data, alcf->table.len);
	mysql_real_escape_string(conn, (char*)esc_user_column, (char*)alcf->user_column.data, alcf->user_column.len);
	mysql_real_escape_string(conn, (char*)esc_user, (char*)uinfo.username.data, uinfo.username.len);

	p = ngx_snprintf(query_buf, NGX_AUTH_MYSQL_MAX_QUERY_LEN, "SELECT `%s` FROM `%s` WHERE `%s` = '%s' LIMIT 1",
		esc_pass_column, esc_table, esc_user_column, esc_user);
	*p = '\0';
	
  	if (mysql_query(conn, (char*)query_buf) != 0) {
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
			"auth_mysql: Could not retrieve password: %s", mysql_error(conn));
		mysql_close(conn);
    	return NGX_HTTP_INTERNAL_SERVER_ERROR;
  	}

	query_result = mysql_store_result(conn);
	if (query_result == NULL){
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
			"auth_mysql: Could not store result: %s", mysql_error(conn));
		mysql_close(conn);
    	return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if (mysql_num_rows(query_result) >= 1) {
		MYSQL_ROW data = mysql_fetch_row(query_result);
		unsigned long *lengths = mysql_fetch_lengths(query_result);
		ngx_str_t volatile_actual_password = {lengths[0], (u_char*) data[0]};
		actual_password.len = lengths[0];
		// strdup will allocate only len bytes, we want an extra one for \0
		volatile_actual_password.len++;
		actual_password.data = ngx_pstrdup(r->pool, &volatile_actual_password);
		actual_password.data[actual_password.len] = '\0';
		mysql_free_result(query_result);
	} else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"auth_mysql: User '%s' doesn't exist.", (char*)uinfo.username.data);
		mysql_free_result(query_result);
		mysql_close(conn);
		return ngx_http_auth_mysql_set_realm(r, &alcf->realm);		
	}
	mysql_close(conn);

	auth_res = NGX_OK;
	auth_res = ngx_http_auth_mysql_enctypes[alcf->encryption_type].checker(r, uinfo.password, actual_password);
	if (NGX_DECLINED == auth_res) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"auth_mysql: Bad authentication for user '%s'.", (char*)uinfo.username.data);
		return ngx_http_auth_mysql_set_realm(r, &alcf->realm);
	}
	/* 
	We expect that on error the checkers log it and then return NGX_ERR. That's why we don't log here, 
	just return NGX_HTTP_INTERNAL_SERVER_ERROR
	*/
    return auth_res == NGX_OK? NGX_OK : NGX_HTTP_INTERNAL_SERVER_ERROR;
}

static ngx_uint_t
ngx_http_auth_mysql_check_plain(ngx_http_request_t *r, ngx_str_t sent_password, ngx_str_t actual_password) {
	return (ngx_strcmp(actual_password.data, sent_password.data) == 0)? NGX_OK : NGX_DECLINED;
}

static ngx_uint_t
ngx_http_auth_mysql_check_md5(ngx_http_request_t *r, ngx_str_t sent_password, ngx_str_t actual_password) {
	u_char md5_str[2*MD5_DIGEST_LENGTH + 1];
	u_char md5_digest[MD5_DIGEST_LENGTH];	
	ngx_md5_t md5;
	
	ngx_md5_init(&md5);
	ngx_md5_update(&md5, sent_password.data, sent_password.len);
	ngx_md5_final(md5_digest, &md5);
	ngx_hex_dump(md5_str, md5_digest, MD5_DIGEST_LENGTH);
	md5_str[2*MD5_DIGEST_LENGTH] = '\0';
	return (ngx_strcmp(actual_password.data, md5_str) == 0)? NGX_OK : NGX_DECLINED;
}

static ngx_uint_t
ngx_http_auth_mysql_check_phpass(ngx_http_request_t *r, ngx_str_t sent_password, ngx_str_t actual_password) {
	if (ngx_strcmp(actual_password.data, crypt_private(r, sent_password.data, actual_password.data))) {
		return ngx_http_auth_mysql_check_md5(r, sent_password, actual_password);
	}
	return NGX_OK;
}

static ngx_int_t
ngx_http_auth_mysql_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

static void *
ngx_http_auth_mysql_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_mysql_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_mysql_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

	conf->port = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_auth_mysql_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_auth_mysql_loc_conf_t *prev = parent;
	ngx_http_auth_mysql_loc_conf_t *conf = child;
	ngx_uint_t enctype_index, enctypes_count;
	
	if (conf->realm.data == NULL) {
        conf->realm = prev->realm;
    }

	/* No point of merging the others if realm is missing*/
	if (conf->realm.data == NULL) {
		return NGX_CONF_OK;
	}	

	ngx_conf_merge_str_value( conf->host, prev->host, "127.0.0.1");
	ngx_conf_merge_str_value( conf->database, prev->database, "");
	ngx_conf_merge_str_value( conf->user, prev->user, "root");
	ngx_conf_merge_str_value( conf->password, prev->password, "");
	ngx_conf_merge_uint_value( conf->port, prev->port, 3306);
	ngx_conf_merge_str_value( conf->table, prev->table, "users");
	ngx_conf_merge_str_value( conf->user_column, prev->user_column, "username");
	ngx_conf_merge_str_value( conf->password_column, prev->password_column, "password");
	ngx_conf_merge_str_value( conf->encryption_type_str, prev->encryption_type_str, "md5");
	ngx_conf_merge_str_value( conf->allowed_users, prev->allowed_users, "");
	
	if (ngx_strcmp(conf->database.data, "") == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
	            "You have to specify a database to use to in auth_mysql_database.");
	    return NGX_CONF_ERROR;
	}
	
	enctypes_count = sizeof(ngx_http_auth_mysql_enctypes) / sizeof(ngx_http_auth_mysql_enctypes[0]);
	for (enctype_index = 0;  enctype_index < enctypes_count; ++enctype_index) {
		if (ngx_strcmp(conf->encryption_type_str.data, ngx_http_auth_mysql_enctypes[enctype_index].id.data) == 0) {
			conf->encryption_type = enctype_index;
			break;
		}		
	}
	
	if (enctype_index >= enctypes_count) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
	            "Unknown encryption type for auth_mysql: %s", conf->encryption_type_str.data);
	    return NGX_CONF_ERROR;							
	}	
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_mysql_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_mysql_handler;

    return NGX_OK;
}

static char *
ngx_http_auth_mysql(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *realm = data;

    size_t   len;
    u_char  *basic, *p;

    if (ngx_strcmp(realm->data, "off") == 0) {
        realm->len = 0;
        realm->data = (u_char *) "";

        return NGX_CONF_OK;
    }

    len = sizeof("Basic realm=\"") - 1 + realm->len + 1;

    basic = ngx_palloc(cf->pool, len);
    if (basic == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    realm->len = len;
    realm->data = basic;

    return NGX_CONF_OK;
}
