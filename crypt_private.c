/*
 * This code exists for the sole purpose to serve as another implementation
 * of the "private" password hashing method implemened in PasswordHash.php
 * and thus to confirm that these password hashes are indeed calculated as
 * intended.
 *
 * Other uses of this code are discouraged.  There are much better password
 * hashing algorithms available to C programmers; one of those is bcrypt:
 *
 *	http://www.openwall.com/crypt/
 *
 * Written by Solar Designer <solar at openwall.com> in 2005 and placed in
 * the public domain.
 *
 * Modified by Nikolay Bachiyski in 2009 to use nginx wrappers and abstractions.
 *
 * There's absolutely no warranty.
 */

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#ifdef TEST
#include <stdio.h>
#endif

#define NGX_AUTH_MYSQL_PHPASS_HASH_LEN 64

static char *itoa64 =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void encode64(u_char *dst, u_char *src, int count)
{
	int i, value;

	i = 0;
	do {
		value = (u_char)src[i++];
		*dst++ = itoa64[value & 0x3f];
		if (i < count)
			value |= (u_char)src[i] << 8;
		*dst++ = itoa64[(value >> 6) & 0x3f];
		if (i++ >= count)
			break;
		if (i < count)
			value |= (u_char)src[i] << 16;
		*dst++ = itoa64[(value >> 12) & 0x3f];
		if (i++ >= count)
			break;
		*dst++ = itoa64[(value >> 18) & 0x3f];
	} while (i < count);
}

u_char *crypt_private(ngx_http_request_t *r, u_char *password, u_char *setting)
{
	u_char *output = ngx_palloc(r->pool, NGX_AUTH_MYSQL_PHPASS_HASH_LEN);
	if (output == NULL) {
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
			"auth_mysql: crypt_private: couldn't allocate memory");		
	}
	ngx_md5_t ctx;
	u_char hash[MD5_DIGEST_LENGTH];
	char *p;
	u_char *salt;
	int count_log2, length, count;

	ngx_memzero(output, NGX_AUTH_MYSQL_PHPASS_HASH_LEN);

	ngx_memcpy(output, "*0", 3);
	if (!ngx_strncmp(setting, output, 2))
		output[1] = '1';

	if (ngx_strncmp(setting, "$P$", 3))
		return output;

	p = ngx_strchr(itoa64, setting[3]);
	if (!p)
		return output;
	count_log2 = p - itoa64;
	if (count_log2 < 7 || count_log2 > 31)
		return output;

	salt = setting + 4;
	if (ngx_strlen(salt) < 8)
		return output;

	length = ngx_strlen(password);

	ngx_md5_init(&ctx);
	ngx_md5_update(&ctx, salt, 8);
	ngx_md5_update(&ctx, password, length);
	ngx_md5_final(hash, &ctx);

	count = 1 << count_log2;
	do {
		ngx_md5_init(&ctx);
		ngx_md5_update(&ctx, hash, MD5_DIGEST_LENGTH);
		ngx_md5_update(&ctx, password, length);
		ngx_md5_final(hash, &ctx);
	} while (--count);

	ngx_memcpy(output, setting, 12);
	encode64(&output[12], hash, MD5_DIGEST_LENGTH);

	return output;
}

#ifdef TEST
int main(int argc, char **argv)
{
	if (argc != 3) return 1;
	puts(crypt_private(argv[1], argv[2]));
	return 0;
}
#endif

