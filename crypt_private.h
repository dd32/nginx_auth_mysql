#ifndef CRYPT_PRIVATE_H
#define CRYPT_PRIVATE_H

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

u_char *crypt_private(ngx_http_request_t *r, u_char *password, u_char *setting);

#endif

