#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include "xattr.h"

#define XATTR_SIZE 10000
#define unlikely(cond) (!!(cond))

#define NDR_PULL_ALIGN(ndr, n) do { \
    if (unlikely(!(ndr->flags & LIBNDR_FLAG_NOALIGN))) {    \
        if (unlikely(ndr->flags & LIBNDR_FLAG_PAD_CHECK)) { \
            ndr_check_padding(ndr, n); \
        } \
        ndr->offset = (ndr->offset + (n-1)) & ~(n-1); \
    } \
    if (unlikely(ndr->offset > ndr->data_size)) {           \
        if (ndr->flags & LIBNDR_FLAG_INCOMPLETE_BUFFER) { \
            uint32_t _missing = ndr->offset - ndr->data_size; \
            ndr->relative_highest_offset = _missing; \
        } \
        return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, "Pull align %u", (unsigned)n); \
    } \
} while(0)

#define NDR_PULL_CHECK_FLAGS(ndr, ndr_flags) do { \
    if ((ndr_flags) & ~(NDR_SCALARS|NDR_BUFFERS)) { \
        return ndr_pull_error(ndr, NDR_ERR_FLAGS, "Invalid pull struct ndr_flags 0x%x", ndr_flags); \
    } \
} while (0)

#define NDR_PULL_NEED_BYTES(ndr, n) do { \
    if (unlikely((n) > ndr->data_size || ndr->offset + (n) > ndr->data_size)) { \
        if (ndr->flags & LIBNDR_FLAG_INCOMPLETE_BUFFER) { \
            uint32_t _available = ndr->data_size - ndr->offset; \
            uint32_t _missing = n - _available; \
            ndr->relative_highest_offset = _missing; \
        } \
        return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, "Pull bytes %u", (unsigned)n); \
    } \
} while(0)

#define NDR_ERR_HAVE_NO_MEMORY(x) do { \
    if (NULL == (x)) { \
        return NDR_ERR_ALLOC; \
    } \
} while (0)

#define DLIST_ADD(list, p) \
do { \
        if (!(list)) { \
        (p)->prev = (list) = (p);  \
        (p)->next = NULL; \
    } else { \
        (p)->prev = (list)->prev; \
        (list)->prev = (p); \
        (p)->next = (list); \
        (list) = (p); \
    } \
} while (0)

#define NDR_BE(ndr) (unlikely(((ndr)->flags & (LIBNDR_FLAG_BIGENDIAN|LIBNDR_FLAG_LITTLE_ENDIAN)) == LIBNDR_FLAG_BIGENDIAN))
#define NDR_SVAL(ndr, ofs) (NDR_BE(ndr)?RSVAL(ndr->data,ofs):SVAL(ndr->data,ofs))


void ndr_check_padding(struct ndr_pull *ndr, size_t n)
{
    size_t ofs2 = (ndr->offset + (n-1)) & ~(n-1);
    int i;
    for (i=ndr->offset;i<ofs2;i++) {
        if (ndr->data[i] != 0) {
            break;
        }
    }
    if (i<ofs2) {
        for (i=ndr->offset;i<ofs2;i++) {
            /*print debug information*/
        }
    }

}


enum ndr_err_code ndr_pull_error(struct ndr_pull *ndr,
                 enum ndr_err_code ndr_err,
                 const char *format, ...)
{
    char *s=NULL;
    va_list ap;
    int ret;

    if (ndr->flags & LIBNDR_FLAG_INCOMPLETE_BUFFER) {
        switch (ndr_err) {
        case NDR_ERR_BUFSIZE:
            return NDR_ERR_INCOMPLETE_BUFFER;
        default:
            break;
        }
    }

    va_start(ap, format);
    ret = vasprintf(&s, format, ap);
    va_end(ap);

    if (ret == -1) {
        return NDR_ERR_ALLOC;
    }
    free(s);

    return ndr_err;
}

enum ndr_err_code ndr_pull_align(struct ndr_pull *ndr, size_t size)
{
    /* this is a nasty hack to make pidl work with NDR64 */
    if (size == 5) {
        if (ndr->flags & LIBNDR_FLAG_NDR64) {
            size = 8;
        } else {
            size = 4;
        }
    } else if (size == 3) {
        if (ndr->flags & LIBNDR_FLAG_NDR64) {
            size = 4;
        } else {
            size = 2;
        }
    }
    NDR_PULL_ALIGN(ndr, size);
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_uint16(struct ndr_pull *ndr, int ndr_flags, uint16_t *v)
{
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    NDR_PULL_ALIGN(ndr, 2);
    NDR_PULL_NEED_BYTES(ndr, 2);
    *v = NDR_SVAL(ndr, ndr->offset);
    ndr->offset += 2;
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_token_store(TALLOC_CTX *mem_ctx,
             struct ndr_token_list **list,
             const void *key,
             uint32_t value)
{
    struct ndr_token_list *tok;
    /*tok = talloc(mem_ctx, struct ndr_token_list);*/
    NDR_ERR_HAVE_NO_MEMORY(tok);
    tok->key = key;
    tok->value = value;
    DLIST_ADD((*list), tok);
    return NDR_ERR_SUCCESS;
}


enum ndr_err_code ndr_pull_set_switch_value(struct ndr_pull *ndr, const void *p, uint32_t val)
{
    return ndr_token_store(ndr, &ndr->switch_list, p, val);
}


enum ndr_err_code ndr_pull_xattr_NTACL(struct ndr_pull *ndr, int ndr_flags, struct xattr_NTACL *r)
{
     NDR_PULL_CHECK_FLAGS(ndr, ndr_flags); 
    if (ndr_flags & NDR_SCALARS) {
        ndr_pull_align(ndr, 5);
        ndr_pull_uint16(ndr, NDR_SCALARS, &r->version);
        ndr_pull_set_switch_value(ndr, &r->info, r->version);
        ndr_pull_xattr_NTACL_Info(ndr, NDR_SCALARS, &r->info);
        ndr_pull_trailer_align(ndr, 5);
    }
    if (ndr_flags & NDR_BUFFERS) {
        ndr_pull_xattr_NTACL_Info(ndr, NDR_BUFFERS, &r->info);
    }
    return NDR_ERR_SUCCESS;
}



void get_blob_from_path(DATA_BLOB *blob, char *value, char *path)
{
    printf("path = %s\n", path);
    int valueLen = getxattr(path, "security.NTACL", value, XATTR_SIZE);
    blob->data = value;
    blob->length = valueLen;
}

int main(int argc, char **argv) 
{
    DATA_BLOB blob;
    char value[XATTR_SIZE];
    get_blob_from_path(&blob, value, argv[1]);

    struct ndr_pull *ndr;
    struct xattr_NTACL xacl;

    ndr->data = blob.data;
    ndr->data_size = blob.length;    

    ndr_pull_xattr_NTACL(ndr, NDR_SCALARS|NDR_BUFFERS, &xacl);
    return 0;
}