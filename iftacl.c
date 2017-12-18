#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include "xattr.h"
#include "byteorder.h"

typedef long long intptr_t ; 

#define XATTR_SIZE 10000
#define likely(cond) (!!(cond))
#define unlikely(cond) (!!(cond))
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))


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

#define NDR_PULL_CHECK_FLAGS(ndr, ndr_flags) do { \
    if ((ndr_flags) & ~(NDR_SCALARS|NDR_BUFFERS)) { \
        return ndr_pull_error(ndr, NDR_ERR_FLAGS, "Invalid pull struct ndr_flags 0x%x", ndr_flags); \
    } \
} while (0)


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

#define NDR_PULL_SET_MEM_CTX(ndr, mem_ctx, flgs) do {\
    if ( !(flgs) || (ndr->flags & flgs) ) {\
        if (!(mem_ctx)) {\
            return ndr_pull_error(ndr, NDR_ERR_ALLOC, "NDR_PULL_SET_MEM_CTX(NULL): %s\n", 0); \
        }\
        ndr->current_mem_ctx = discard_const(mem_ctx);\
    }\
} while(0)

#define NDR_PULL_ALLOC(ndr, s) do { \
    _NDR_PULL_FIX_CURRENT_MEM_CTX(ndr);\
    (s) = talloc_ptrtype(ndr->current_mem_ctx, (s)); \
    if (unlikely(!(s))) return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Alloc %s failed: %s\n", # s, 0); \
} while (0)

#define _NDR_PULL_FIX_CURRENT_MEM_CTX(ndr) do {\
    if (!ndr->current_mem_ctx) {\
        ndr->current_mem_ctx = talloc_new(ndr);\
        if (!ndr->current_mem_ctx) {\
            return ndr_pull_error(ndr, NDR_ERR_ALLOC, "_NDR_PULL_FIX_CURRENT_MEM_CTX() failed: %s\n", 0); \
        }\
    }\
} while(0)

#define NDR_PULL_GET_MEM_CTX(ndr) (ndr->current_mem_ctx)

#define NDR_ERR_CODE_IS_SUCCESS(x) (x == NDR_ERR_SUCCESS)

#define NDR_CHECK(call) do { \
    enum ndr_err_code _status; \
    _status = call; \
    if (unlikely(!NDR_ERR_CODE_IS_SUCCESS(_status))) {  \
        return _status; \
    } \
} while (0)

#define NDR_PULL_ALLOC_N(ndr, s, n) do { \
    _NDR_PULL_FIX_CURRENT_MEM_CTX(ndr);\
    (s) = talloc_array_ptrtype(ndr->current_mem_ctx, (s), n); \
    if (unlikely(!(s))) return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Alloc %u * %s failed: %s\n", (unsigned)n, # s, 0); \
} while (0)

typedef int (*comparison_fn_t)(const void *, const void *);

#define NDR_BE(ndr) (unlikely(((ndr)->flags & (LIBNDR_FLAG_BIGENDIAN|LIBNDR_FLAG_LITTLE_ENDIAN)) == LIBNDR_FLAG_BIGENDIAN))
#define NDR_SVAL(ndr, ofs) (NDR_BE(ndr)?RSVAL(ndr->data,ofs):SVAL(ndr->data,ofs))
#define NDR_IVAL(ndr, ofs) (NDR_BE(ndr)?RIVAL(ndr->data,ofs):IVAL(ndr->data,ofs))
#define MIN(a,b) ((a) < (b) ? (a) : (b))
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

/*
   remove an element from a list
   Note that the element doesn't have to be in the list. If it
   isn't then this is a no-op
*/
#define DLIST_REMOVE(list, p) \
do { \
    if ((p) == (list)) { \
        if ((p)->next) (p)->next->prev = (p)->prev; \
        (list) = (p)->next; \
    } else if ((list) && (p) == (list)->prev) { \
        (p)->prev->next = NULL; \
        (list)->prev = (p)->prev; \
    } else { \
        if ((p)->prev) (p)->prev->next = (p)->next; \
        if ((p)->next) (p)->next->prev = (p)->prev; \
    } \
    if ((p) != (list)) (p)->next = (p)->prev = NULL;    \
} while (0)

#define NDR_ERR_HAVE_NO_MEMORY(x) do { \
    if (NULL == (x)) { \
        return NDR_ERR_ALLOC; \
    } \
} while (0)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + _array_size_chk(arr))
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#define _array_size_chk(arr) 0

#define SEC_ACE_OBJECT_TYPE_PRESENT ( 0x00000001 )
#define SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT ( 0x00000002 )

typedef enum {CH_UTF16LE=0, CH_UTF16=0, CH_UNIX, CH_DOS, CH_UTF8, CH_UTF16BE, CH_UTF16MUNGED} charset_t;

struct dom_sid {
    uint8_t sid_rev_num;
    int8_t num_auths;/* [range(0,15)] */
    uint8_t id_auth[6];
    uint32_t sub_auths[15];
}/* [gensize,noprint,nopull,nopush,nosize,public] */;

enum security_descriptor_revision
{
    SECURITY_DESCRIPTOR_REVISION_1=(int)(1)
};

enum security_acl_revision
{
    SECURITY_ACL_REVISION_NT4=(int)(2),
    SECURITY_ACL_REVISION_ADS=(int)(4)
};

enum security_ace_type
{
    SEC_ACE_TYPE_ACCESS_ALLOWED=(int)(0),
    SEC_ACE_TYPE_ACCESS_DENIED=(int)(1),
    SEC_ACE_TYPE_SYSTEM_AUDIT=(int)(2),
    SEC_ACE_TYPE_SYSTEM_ALARM=(int)(3),
    SEC_ACE_TYPE_ALLOWED_COMPOUND=(int)(4),
    SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT=(int)(5),
    SEC_ACE_TYPE_ACCESS_DENIED_OBJECT=(int)(6),
    SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT=(int)(7),
    SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT=(int)(8)
};

struct GUID {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq[2];
    uint8_t node[6];
};

union security_ace_object_type {
    struct GUID type;/* [case(SEC_ACE_OBJECT_TYPE_PRESENT)] */
}/* [nodiscriminant] */;

union security_ace_object_inherited_type {
    struct GUID inherited_type;/* [case(SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT)] */
}/* [nodiscriminant] */;

struct security_ace_object {
    uint32_t flags;
    union security_ace_object_type type;/* [switch_is(flags&SEC_ACE_OBJECT_TYPE_PRESENT)] */
    union security_ace_object_inherited_type inherited_type;/* [switch_is(flags&SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT)] */
};

union security_ace_object_ctr {
    struct security_ace_object object;/* [case(SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT)] */
}/* [nodiscriminant,public] */;

struct security_ace {
    enum security_ace_type type;
    uint8_t flags;
    uint16_t size;/* [value(ndr_size_security_ace(r,ndr->flags))] */
    uint32_t access_mask;
    union security_ace_object_ctr object;/* [switch_is(type)] */
    struct dom_sid trustee;
}/* [gensize,nopull,nosize,public] */;


struct security_acl {
    enum security_acl_revision revision;
    uint16_t size;/* [value(ndr_size_security_acl(r,ndr->flags))] */
    uint32_t num_aces;/* [range(0,2000)] */
    struct security_ace *aces;
}/* [gensize,nosize,public] */;

struct security_descriptor {
    enum security_descriptor_revision revision;
    uint16_t type;
    struct dom_sid *owner_sid;/* [relative] */
    struct dom_sid *group_sid;/* [relative] */
    struct security_acl *sacl;/* [relative] */
    struct security_acl *dacl;/* [relative] */
}/* [flag(LIBNDR_FLAG_LITTLE_ENDIAN),gensize,nosize,public] */;



size_t ascii_len_n(const char *src, size_t n)
{
    size_t len;

    len = strnlen(src, n);
    if (len+1 <= n) {
        len += 1;
    }

    return len;
}

size_t utf16_len_n(const void *src, size_t n)
{
    size_t len;

    for (len = 0; (len+2 < n) && SVAL(src, len); len += 2) ;

    if (len+2 <= n) {
        len += 2;
    }

    return len;
}

/*
  advance by 'size' bytes
*/
enum ndr_err_code ndr_pull_advance(struct ndr_pull *ndr, uint32_t size)
{
    ndr->offset += size;
    if (ndr->offset > ndr->data_size) {
        return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,
                      "ndr_pull_advance by %u failed",
                      size);
    }
    return NDR_ERR_SUCCESS;
}


enum ndr_err_code ndr_pull_bytes(struct ndr_pull *ndr, uint8_t *data, uint32_t n)
{
    NDR_PULL_NEED_BYTES(ndr, n);
    memcpy(data, ndr->data + ndr->offset, n);
    ndr->offset += n;
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_array_uint8(struct ndr_pull *ndr, int ndr_flags, uint8_t *data, uint32_t n)
{
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    if (!(ndr_flags & NDR_SCALARS)) {
        return NDR_ERR_SUCCESS;
    }
    return ndr_pull_bytes(ndr, data, n);
}

/*
  parse a uint8_t
*/
enum ndr_err_code ndr_pull_uint8(struct ndr_pull *ndr, int ndr_flags, uint8_t *v)
{
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    NDR_PULL_NEED_BYTES(ndr, 1);
    *v = CVAL(ndr->data, ndr->offset);
    ndr->offset += 1;
    return NDR_ERR_SUCCESS;
}


/*
  parse a uint8_t enum
*/
enum ndr_err_code ndr_pull_enum_uint8(struct ndr_pull *ndr, int ndr_flags, uint8_t *v)
{
    return ndr_pull_uint8(ndr, ndr_flags, v);
}

/*
  parse a int8_t
*/
enum ndr_err_code ndr_pull_int8(struct ndr_pull *ndr, int ndr_flags, int8_t *v)
{
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    NDR_PULL_NEED_BYTES(ndr, 1);
    *v = (int8_t)CVAL(ndr->data, ndr->offset);
    ndr->offset += 1;
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

enum ndr_err_code ndr_pull_uint32(struct ndr_pull *ndr, int ndr_flags, uint32_t *v)
{
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    NDR_PULL_ALIGN(ndr, 4);
    NDR_PULL_NEED_BYTES(ndr, 4);
    *v = NDR_IVAL(ndr, ndr->offset);
    ndr->offset += 4;
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_udlong(struct ndr_pull *ndr, int ndr_flags, uint64_t *v)
{
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    NDR_PULL_ALIGN(ndr, 4);
    NDR_PULL_NEED_BYTES(ndr, 8);
    *v = NDR_IVAL(ndr, ndr->offset);
    *v |= (uint64_t)(NDR_IVAL(ndr, ndr->offset+4)) << 32;
    ndr->offset += 8;
    return NDR_ERR_SUCCESS;
}


enum ndr_err_code ndr_pull_udlongr(struct ndr_pull *ndr, int ndr_flags, uint64_t *v)
{
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    NDR_PULL_ALIGN(ndr, 4);
    NDR_PULL_NEED_BYTES(ndr, 8);
    *v = ((uint64_t)NDR_IVAL(ndr, ndr->offset)) << 32;
    *v |= NDR_IVAL(ndr, ndr->offset+4);
    ndr->offset += 8;
    return NDR_ERR_SUCCESS;
}


enum ndr_err_code ndr_pull_hyper(struct ndr_pull *ndr, int ndr_flags, uint64_t *v)
{
    NDR_PULL_ALIGN(ndr, 8);
    if (NDR_BE(ndr)) {
        return ndr_pull_udlongr(ndr, ndr_flags, v);
    }
    return ndr_pull_udlong(ndr, ndr_flags, v);
}


enum ndr_err_code ndr_pull_uint3264(struct ndr_pull *ndr, int ndr_flags, uint32_t *v)
{
    uint64_t v64;
    enum ndr_err_code err;
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    if (likely(!(ndr->flags & LIBNDR_FLAG_NDR64))) {
        return ndr_pull_uint32(ndr, ndr_flags, v);
    }
    err = ndr_pull_hyper(ndr, ndr_flags, &v64);
    *v = (uint32_t)v64;
    if (unlikely(v64 != *v)) {
        return ndr_pull_error(ndr, NDR_ERR_NDR64, ": non-zero upper 32 bits 0x%016llx\n",
             (unsigned long long)v64);
    }
    return err;
}

/*
  parse a uint1632_t enum (uint32_t on NDR64)
*/
enum ndr_err_code ndr_pull_enum_uint1632(struct ndr_pull *ndr, int ndr_flags, uint16_t *v)
{
    if (unlikely(ndr->flags & LIBNDR_FLAG_NDR64)) {
        uint32_t v32;
        NDR_CHECK(ndr_pull_uint32(ndr, ndr_flags, &v32));
        *v = v32;
        if (v32 != *v) {
            return NDR_ERR_NDR64;
        }
        return NDR_ERR_SUCCESS;
    }
    return ndr_pull_uint16(ndr, ndr_flags, v);
}



/*
  set the parse offset to 'ofs'
*/
enum ndr_err_code ndr_pull_set_offset(struct ndr_pull *ndr, uint32_t ofs)
{
    ndr->offset = ofs;
    if (ndr->offset > ndr->data_size) {
        return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,
                      "ndr_pull_set_offset %u failed",
                      ofs);
    }
    return NDR_ERR_SUCCESS;
}



/*
  pull a NTTIME
*/
enum ndr_err_code ndr_pull_NTTIME(struct ndr_pull *ndr, int ndr_flags, NTTIME *t)
{
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    NDR_CHECK(ndr_pull_udlong(ndr, ndr_flags, t));
    return NDR_ERR_SUCCESS;
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

enum ndr_err_code ndr_pull_trailer_align(struct ndr_pull *ndr, size_t size)
{
    /* MS-RPCE section 2.2.5.3.4.1 */
    if (ndr->flags & LIBNDR_FLAG_NDR64) {
        return ndr_pull_align(ndr, size);
    }
    return NDR_ERR_SUCCESS;
}


enum ndr_err_code ndr_pull_string(struct ndr_pull *ndr, int ndr_flags, const char **s)
{
	char *as=NULL;
	uint32_t len1, ofs, len2;
	uint16_t len3;
	size_t conv_src_len = 0, converted_size;
	int do_convert = 1, chset = CH_UTF16;
	unsigned byte_mul = 2;
	unsigned flags = ndr->flags;
	unsigned c_len_term = 0;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr)) {
		chset = CH_UTF16BE;
	}

	if (flags & LIBNDR_FLAG_STR_ASCII) {
		chset = CH_DOS;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_ASCII;
	}

	if (flags & LIBNDR_FLAG_STR_UTF8) {
		chset = CH_UTF8;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_UTF8;
	}

	if (flags & LIBNDR_FLAG_STR_RAW8) {
		do_convert = 0;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_RAW8;
	}

	flags &= ~LIBNDR_FLAG_STR_CONFORMANT;
	if (flags & LIBNDR_FLAG_STR_CHARLEN) {
		c_len_term = 1;
		flags &= ~LIBNDR_FLAG_STR_CHARLEN;
	}

	switch (flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &ofs));
		if (ofs != 0) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "non-zero array offset with string flags 0x%x\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len2));
		if (len2 > len1) {
			return ndr_pull_error(ndr, NDR_ERR_STRING,
					      "Bad string lengths len1=%u ofs=%u len2=%u\n",
					      len1, ofs, len2);
		} else if (len1 != len2) {
			/*DEBUG(6,("len1[%u] != len2[%u] '%s'\n", len1, len2, as));*/
		}
		conv_src_len = len2 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		conv_src_len = len1 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_LEN4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &ofs));
		if (ofs != 0) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "non-zero array offset with string flags 0x%x\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		conv_src_len = len1 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE2:
	case LIBNDR_FLAG_STR_SIZE2|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &len3));
		conv_src_len = len3 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE2|LIBNDR_FLAG_STR_NOTERM|LIBNDR_FLAG_STR_BYTESIZE:
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &len3));
		conv_src_len = len3;
		byte_mul = 1; /* the length is now absolute */
		break;

	case LIBNDR_FLAG_STR_NULLTERM:
		if (byte_mul == 1) {
			conv_src_len = ascii_len_n((const char *)(ndr->data+ndr->offset), ndr->data_size - ndr->offset);
		} else {
			conv_src_len = utf16_len_n(ndr->data+ndr->offset, ndr->data_size - ndr->offset);
		}
		byte_mul = 1; /* the length is now absolute */
		break;

	case LIBNDR_FLAG_STR_NOTERM:
		if (!(ndr->flags & LIBNDR_FLAG_REMAINING)) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x (missing NDR_REMAINING)\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		conv_src_len = ndr->data_size - ndr->offset;
		byte_mul = 1; /* the length is now absolute */
		break;

	default:
		return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	NDR_PULL_NEED_BYTES(ndr, conv_src_len * byte_mul);
	if (conv_src_len == 0) {
		as = talloc_strdup(ndr->current_mem_ctx, "");
		converted_size = 0;
	} else {
		if (!do_convert) {
			as = talloc_strndup(ndr->current_mem_ctx,
			                    (char *)ndr->data + ndr->offset,
					    conv_src_len);
			if (!as) {
				return ndr_pull_error(ndr, NDR_ERR_ALLOC,
						      "Failed to talloc_strndup() in RAW8 ndr_string_pull()");
			}
			converted_size = MIN(strlen(as)+1, conv_src_len);
		} else if (!convert_string_talloc(ndr->current_mem_ctx, chset,
					   CH_UNIX, ndr->data + ndr->offset,
					   conv_src_len * byte_mul,
					   (void **)(void *)&as,
					   &converted_size)) {
			return ndr_pull_error(ndr, NDR_ERR_CHARCNV,
					      "Bad character conversion with flags 0x%x", flags);
		}
	}

	/* this is a way of detecting if a string is sent with the wrong
	   termination */
	if (ndr->flags & LIBNDR_FLAG_STR_NOTERM) {
		if (as && converted_size > 0 && as[converted_size-1] == '\0') {
			/*DEBUG(6,("short string '%s', sent with NULL termination despite NOTERM flag in IDL\n", as));*/
		}
	} else {
		if (as && converted_size > 0 && as[converted_size-1] != '\0') {
			/*DEBUG(6,("long string '%s', send without NULL termination (which was expected)\n", as));*/
		}
	}

	NDR_CHECK(ndr_pull_advance(ndr, conv_src_len * byte_mul));
	*s = as;

	return NDR_ERR_SUCCESS;
}


enum ndr_err_code ndr_pull_generic_ptr(struct ndr_pull *ndr, uint32_t *v)
{
    NDR_CHECK(ndr_pull_uint3264(ndr, NDR_SCALARS, v));
    if (*v != 0) {
        ndr->ptr_count++;
    }
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_union_align(struct ndr_pull *ndr, size_t size)
{
    /* MS-RPCE section 2.2.5.3.4.4 */
    if (ndr->flags & LIBNDR_FLAG_NDR64) {
        return ndr_pull_align(ndr, size);
    }
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_token_retrieve_cmp_fn(struct ndr_token_list **list, const void *key, uint32_t *v,
                   comparison_fn_t _cmp_fn, bool _remove_tok)
{
    struct ndr_token_list *tok;
    for (tok=*list;tok;tok=tok->next) {
        if (_cmp_fn && _cmp_fn(tok->key,key)==0) goto found;
        else if (!_cmp_fn && tok->key == key) goto found;
    }
    return NDR_ERR_TOKEN;
found:
    *v = tok->value;
    if (_remove_tok) {
        DLIST_REMOVE((*list), tok);
        talloc_free(tok);
    }
    return NDR_ERR_SUCCESS;
}


/*
  retrieve a token from a ndr context
*/
enum ndr_err_code ndr_token_retrieve(struct ndr_token_list **list, const void *key, uint32_t *v)
{
    return ndr_token_retrieve_cmp_fn(list, key, v, NULL, true);
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
/*
  pull a relative object - stage1
  called during SCALARS processing
*/
enum ndr_err_code ndr_pull_relative_ptr1(struct ndr_pull *ndr, const void *p, uint32_t rel_offset)
{
    rel_offset += ndr->relative_base_offset;
    if (rel_offset > ndr->data_size) {
        return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,
                      "ndr_pull_relative_ptr1 rel_offset(%u) > ndr->data_size(%u)",
                      rel_offset, ndr->data_size);
    }
    return ndr_token_store(ndr, &ndr->relative_list, p, rel_offset);
}
/*
  pull a relative object - stage2
  called during BUFFERS processing
*/
enum ndr_err_code ndr_pull_relative_ptr2(struct ndr_pull *ndr, const void *p)
{
    uint32_t rel_offset;
    NDR_CHECK(ndr_token_retrieve(&ndr->relative_list, p, &rel_offset));
    return ndr_pull_set_offset(ndr, rel_offset);
}


enum ndr_err_code ndr_pull_security_descriptor_revision(struct ndr_pull *ndr, int ndr_flags, enum security_descriptor_revision *r)
{
	uint8_t v = 1;
	NDR_CHECK(ndr_pull_enum_uint8(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_security_descriptor_type(struct ndr_pull *ndr, int ndr_flags, uint16_t *r)
{
	uint16_t v;
	NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_dom_sid(struct ndr_pull *ndr, int ndr_flags, struct dom_sid *r)
{
    uint32_t cntr_sub_auths_0;
    if (ndr_flags & NDR_SCALARS) {
        NDR_CHECK(ndr_pull_align(ndr, 4));
        NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->sid_rev_num));
        NDR_CHECK(ndr_pull_int8(ndr, NDR_SCALARS, &r->num_auths));
        if (r->num_auths < 0 || r->num_auths > ARRAY_SIZE(r->sub_auths)) {
            return ndr_pull_error(ndr, NDR_ERR_RANGE, "value out of range");
        }
        NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->id_auth, 6));
        ZERO_STRUCT(r->sub_auths);
        for (cntr_sub_auths_0 = 0; cntr_sub_auths_0 < r->num_auths; cntr_sub_auths_0++) {
            NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->sub_auths[cntr_sub_auths_0]));
        }
    }
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_security_acl_revision(struct ndr_pull *ndr, int ndr_flags, enum security_acl_revision *r)
{
	uint16_t v;
	NDR_CHECK(ndr_pull_enum_uint1632(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_security_ace_type(struct ndr_pull *ndr, int ndr_flags, enum security_ace_type *r)
{
    uint8_t v;
    NDR_CHECK(ndr_pull_enum_uint8(ndr, NDR_SCALARS, &v));
    *r = v;
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_security_ace_flags(struct ndr_pull *ndr, int ndr_flags, uint8_t *r)
{
    uint8_t v;
    NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &v));
    *r = v;
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_set_switch_value(struct ndr_pull *ndr, const void *p, uint32_t val)
{
    return ndr_token_store(ndr, &ndr->switch_list, p, val);
}

static enum ndr_err_code ndr_pull_security_ace_object_flags(struct ndr_pull *ndr, int ndr_flags, uint32_t *r)
{
	uint32_t v;
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

/*
  peek at but don't removed a token from a ndr context
*/
uint32_t ndr_token_peek(struct ndr_token_list **list, const void *key)
{
    enum ndr_err_code status;
    uint32_t v;

    status = ndr_token_retrieve_cmp_fn(list, key, &v, NULL, false);
    if (!NDR_ERR_CODE_IS_SUCCESS(status)) {
        return 0;
    }

    return v;
}

uint32_t ndr_pull_get_switch_value(struct ndr_pull *ndr, const void *p)
{
    return ndr_token_peek(&ndr->switch_list, p);
}

enum ndr_err_code ndr_pull_GUID(struct ndr_pull *ndr, int ndr_flags, struct GUID *r)
{
    uint32_t size_clock_seq_0 = 0;
    uint32_t size_node_0 = 0;
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    if (ndr_flags & NDR_SCALARS) {
        NDR_CHECK(ndr_pull_align(ndr, 4));
        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->time_low));
        NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->time_mid));
        NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->time_hi_and_version));
        size_clock_seq_0 = 2;
        NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->clock_seq, size_clock_seq_0));
        size_node_0 = 6;
        NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->node, size_node_0));
        NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
    }
    if (ndr_flags & NDR_BUFFERS) {
    }
    return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_security_ace_object_inherited_type(struct ndr_pull *ndr, int ndr_flags, union security_ace_object_inherited_type *r)
{
	uint32_t level;
	level = ndr_pull_get_switch_value(ndr, r);
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_union_align(ndr, 4));
		switch (level) {
			case SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT: {
				NDR_CHECK(ndr_pull_GUID(ndr, NDR_SCALARS, &r->inherited_type));
			break; }

			default: {
			break; }

		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		switch (level) {
			case SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT:
			break;

			default:
			break;

		}
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_security_ace_object_type(struct ndr_pull *ndr, int ndr_flags, union security_ace_object_type *r)
{
	uint32_t level;
	level = ndr_pull_get_switch_value(ndr, r);
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_union_align(ndr, 4));
		switch (level) {
			case SEC_ACE_OBJECT_TYPE_PRESENT: {
				NDR_CHECK(ndr_pull_GUID(ndr, NDR_SCALARS, &r->type));
			break; }

			default: {
			break; }

		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		switch (level) {
			case SEC_ACE_OBJECT_TYPE_PRESENT:
			break;

			default:
			break;

		}
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_security_ace_object(struct ndr_pull *ndr, int ndr_flags, struct security_ace_object *r)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_security_ace_object_flags(ndr, NDR_SCALARS, &r->flags));
		NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->type, r->flags & SEC_ACE_OBJECT_TYPE_PRESENT));
		NDR_CHECK(ndr_pull_security_ace_object_type(ndr, NDR_SCALARS, &r->type));
		NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->inherited_type, r->flags & SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT));
		NDR_CHECK(ndr_pull_security_ace_object_inherited_type(ndr, NDR_SCALARS, &r->inherited_type));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_pull_security_ace_object_type(ndr, NDR_BUFFERS, &r->type));
		NDR_CHECK(ndr_pull_security_ace_object_inherited_type(ndr, NDR_BUFFERS, &r->inherited_type));
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_security_ace_object_ctr(struct ndr_pull *ndr, int ndr_flags, union security_ace_object_ctr *r)
{
	uint32_t level;
	level = ndr_pull_get_switch_value(ndr, r);
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_union_align(ndr, 4));
		switch (level) {
			case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT: {
				NDR_CHECK(ndr_pull_security_ace_object(ndr, NDR_SCALARS, &r->object));
			break; }

			case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT: {
				NDR_CHECK(ndr_pull_security_ace_object(ndr, NDR_SCALARS, &r->object));
			break; }

			case SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT: {
				NDR_CHECK(ndr_pull_security_ace_object(ndr, NDR_SCALARS, &r->object));
			break; }

			case SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT: {
				NDR_CHECK(ndr_pull_security_ace_object(ndr, NDR_SCALARS, &r->object));
			break; }

			default: {
			break; }

		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		switch (level) {
			case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT:
				NDR_CHECK(ndr_pull_security_ace_object(ndr, NDR_BUFFERS, &r->object));
			break;

			case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT:
				NDR_CHECK(ndr_pull_security_ace_object(ndr, NDR_BUFFERS, &r->object));
			break;

			case SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT:
				NDR_CHECK(ndr_pull_security_ace_object(ndr, NDR_BUFFERS, &r->object));
			break;

			case SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT:
				NDR_CHECK(ndr_pull_security_ace_object(ndr, NDR_BUFFERS, &r->object));
			break;

			default:
			break;

		}
	}
	return NDR_ERR_SUCCESS;
}


enum ndr_err_code ndr_pull_security_ace(struct ndr_pull *ndr, int ndr_flags, struct security_ace *r)
{
    if (ndr_flags & NDR_SCALARS) {
        uint32_t start_ofs = ndr->offset;
        uint32_t size = 0;
        uint32_t pad = 0;
        NDR_CHECK(ndr_pull_align(ndr, 4));
        NDR_CHECK(ndr_pull_security_ace_type(ndr, NDR_SCALARS, &r->type));
        NDR_CHECK(ndr_pull_security_ace_flags(ndr, NDR_SCALARS, &r->flags));
        NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->size));
        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->access_mask));
        NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->object, r->type));
        NDR_CHECK(ndr_pull_security_ace_object_ctr(ndr, NDR_SCALARS, &r->object));
        NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, &r->trustee));
        size = ndr->offset - start_ofs;
        if (r->size < size) {
            return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,
                          "ndr_pull_security_ace: r->size %u < size %u",
                          (unsigned)r->size, size);
        }
        pad = r->size - size;
        NDR_PULL_NEED_BYTES(ndr, pad);
        ndr->offset += pad;
    }
    if (ndr_flags & NDR_BUFFERS) {
        NDR_CHECK(ndr_pull_security_ace_object_ctr(ndr, NDR_BUFFERS, &r->object));
    }
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_security_acl(struct ndr_pull *ndr, int ndr_flags, struct security_acl *r)
{
	uint32_t size_aces_0 = 0;
	uint32_t cntr_aces_0;
	TALLOC_CTX *_mem_save_aces_0;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_security_acl_revision(ndr, NDR_SCALARS, &r->revision));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->size));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->num_aces));
		if (r->num_aces > 2000) {
			return ndr_pull_error(ndr, NDR_ERR_RANGE, "value out of range");
		}
		size_aces_0 = r->num_aces;
		NDR_PULL_ALLOC_N(ndr, r->aces, size_aces_0);
		_mem_save_aces_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->aces, 0);
		for (cntr_aces_0 = 0; cntr_aces_0 < size_aces_0; cntr_aces_0++) {
			NDR_CHECK(ndr_pull_security_ace(ndr, NDR_SCALARS, &r->aces[cntr_aces_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_aces_0, 0);
		NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
	}
	if (ndr_flags & NDR_BUFFERS) {
		size_aces_0 = r->num_aces;
		_mem_save_aces_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->aces, 0);
		for (cntr_aces_0 = 0; cntr_aces_0 < size_aces_0; cntr_aces_0++) {
			NDR_CHECK(ndr_pull_security_ace(ndr, NDR_BUFFERS, &r->aces[cntr_aces_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_aces_0, 0);
	}
	return NDR_ERR_SUCCESS;
}


enum ndr_err_code ndr_pull_security_descriptor(struct ndr_pull *ndr, int ndr_flags, struct security_descriptor *r)
{
	uint32_t _ptr_owner_sid;
	TALLOC_CTX *_mem_save_owner_sid_0;
	uint32_t _ptr_group_sid;
	TALLOC_CTX *_mem_save_group_sid_0;
	uint32_t _ptr_sacl;
	TALLOC_CTX *_mem_save_sacl_0;
	uint32_t _ptr_dacl;
	TALLOC_CTX *_mem_save_dacl_0;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_LITTLE_ENDIAN);
		NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
		if (ndr_flags & NDR_SCALARS) {
			NDR_CHECK(ndr_pull_align(ndr, 5));
			NDR_CHECK(ndr_pull_security_descriptor_revision(ndr, NDR_SCALARS, &r->revision));
			NDR_CHECK(ndr_pull_security_descriptor_type(ndr, NDR_SCALARS, &r->type));
			NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_owner_sid));
			if (_ptr_owner_sid) {
				NDR_PULL_ALLOC(ndr, r->owner_sid);
				NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->owner_sid, _ptr_owner_sid));
			} else {
				r->owner_sid = NULL;
			}
			NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_group_sid));
			if (_ptr_group_sid) {
				NDR_PULL_ALLOC(ndr, r->group_sid);
				NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->group_sid, _ptr_group_sid));
			} else {
				r->group_sid = NULL;
			}
			NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_sacl));
			if (_ptr_sacl) {
				NDR_PULL_ALLOC(ndr, r->sacl);
				NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->sacl, _ptr_sacl));
			} else {
				r->sacl = NULL;
			}
			NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_dacl));
			if (_ptr_dacl) {
				NDR_PULL_ALLOC(ndr, r->dacl);
				NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->dacl, _ptr_dacl));
			} else {
				r->dacl = NULL;
			}
			NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
		}
		if (ndr_flags & NDR_BUFFERS) {
			if (r->owner_sid) {
				uint32_t _relative_save_offset;
				_relative_save_offset = ndr->offset;
				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->owner_sid));
				_mem_save_owner_sid_0 = NDR_PULL_GET_MEM_CTX(ndr);
				NDR_PULL_SET_MEM_CTX(ndr, r->owner_sid, 0);
				NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, r->owner_sid));
				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_owner_sid_0, 0);
				if (ndr->offset > ndr->relative_highest_offset) {
					ndr->relative_highest_offset = ndr->offset;
				}
				ndr->offset = _relative_save_offset;
			}
			if (r->group_sid) {
				uint32_t _relative_save_offset;
				_relative_save_offset = ndr->offset;
				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->group_sid));
				_mem_save_group_sid_0 = NDR_PULL_GET_MEM_CTX(ndr);
				NDR_PULL_SET_MEM_CTX(ndr, r->group_sid, 0);
				NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, r->group_sid));
				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_group_sid_0, 0);
				if (ndr->offset > ndr->relative_highest_offset) {
					ndr->relative_highest_offset = ndr->offset;
				}
				ndr->offset = _relative_save_offset;
			}
			if (r->sacl) {
				uint32_t _relative_save_offset;
				_relative_save_offset = ndr->offset;
				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->sacl));
				_mem_save_sacl_0 = NDR_PULL_GET_MEM_CTX(ndr);
				NDR_PULL_SET_MEM_CTX(ndr, r->sacl, 0);
				NDR_CHECK(ndr_pull_security_acl(ndr, NDR_SCALARS|NDR_BUFFERS, r->sacl));
				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sacl_0, 0);
				if (ndr->offset > ndr->relative_highest_offset) {
					ndr->relative_highest_offset = ndr->offset;
				}
				ndr->offset = _relative_save_offset;
			}
			if (r->dacl) {
				uint32_t _relative_save_offset;
				_relative_save_offset = ndr->offset;
				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->dacl));
				_mem_save_dacl_0 = NDR_PULL_GET_MEM_CTX(ndr);
				NDR_PULL_SET_MEM_CTX(ndr, r->dacl, 0);
				NDR_CHECK(ndr_pull_security_acl(ndr, NDR_SCALARS|NDR_BUFFERS, r->dacl));
				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_dacl_0, 0);
				if (ndr->offset > ndr->relative_highest_offset) {
					ndr->relative_highest_offset = ndr->offset;
				}
				ndr->offset = _relative_save_offset;
			}
		}
		ndr->flags = _flags_save_STRUCT;
	}
	return NDR_ERR_SUCCESS;
}




void ndr_set_flags(uint32_t *pflags, uint32_t new_flags)
{
    /* the big/little endian flags are inter-dependent */
    if (new_flags & LIBNDR_FLAG_LITTLE_ENDIAN) {
        (*pflags) &= ~LIBNDR_FLAG_BIGENDIAN;
        (*pflags) &= ~LIBNDR_FLAG_NDR64;
    }
    if (new_flags & LIBNDR_FLAG_BIGENDIAN) {
        (*pflags) &= ~LIBNDR_FLAG_LITTLE_ENDIAN;
        (*pflags) &= ~LIBNDR_FLAG_NDR64;
    }
    if (new_flags & LIBNDR_ALIGN_FLAGS) {
        /* Ensure we only have the passed-in
           align flag set in the new_flags,
           remove any old align flag. */
        (*pflags) &= ~LIBNDR_ALIGN_FLAGS;
    }
    if (new_flags & LIBNDR_FLAG_NO_RELATIVE_REVERSE) {
        (*pflags) &= ~LIBNDR_FLAG_RELATIVE_REVERSE;
    }
    (*pflags) |= new_flags;
}


enum ndr_err_code ndr_pull_security_descriptor_hash_v4(struct ndr_pull *ndr, int ndr_flags, struct security_descriptor_hash_v4 *r)
{
	uint32_t _ptr_sd;
	TALLOC_CTX *_mem_save_sd_0;
	uint32_t size_hash_0 = 0;
	uint32_t size_sys_acl_hash_0 = 0;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_sd));
		if (_ptr_sd) {
			NDR_PULL_ALLOC(ndr, r->sd);
		} else {
			r->sd = NULL;
		}
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->hash_type));
		size_hash_0 = 64;
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->hash, size_hash_0));
		{
			uint32_t _flags_save_string = ndr->flags;
			ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_UTF8|LIBNDR_FLAG_STR_NULLTERM);
			NDR_CHECK(ndr_pull_string(ndr, NDR_SCALARS, &r->description));
			ndr->flags = _flags_save_string;
		}
		NDR_CHECK(ndr_pull_NTTIME(ndr, NDR_SCALARS, &r->time));
		size_sys_acl_hash_0 = 64;
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->sys_acl_hash, size_sys_acl_hash_0));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->sd) {
			_mem_save_sd_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->sd, 0);
			NDR_CHECK(ndr_pull_security_descriptor(ndr, NDR_SCALARS|NDR_BUFFERS, r->sd));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sd_0, 0);
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_security_descriptor_hash_v2(struct ndr_pull *ndr, int ndr_flags, struct security_descriptor_hash_v2 *r)
{
	uint32_t _ptr_sd;
	TALLOC_CTX *_mem_save_sd_0;
	uint32_t size_hash_0 = 0;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_sd));
		if (_ptr_sd) {
			NDR_PULL_ALLOC(ndr, r->sd);
		} else {
			r->sd = NULL;
		}
		size_hash_0 = 16;
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->hash, size_hash_0));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->sd) {
			_mem_save_sd_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->sd, 0);
			NDR_CHECK(ndr_pull_security_descriptor(ndr, NDR_SCALARS|NDR_BUFFERS, r->sd));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sd_0, 0);
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_security_descriptor_hash_v3(struct ndr_pull *ndr, int ndr_flags, struct security_descriptor_hash_v3 *r)
{
	uint32_t _ptr_sd;
	TALLOC_CTX *_mem_save_sd_0;
	uint32_t size_hash_0 = 0;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_sd));
		if (_ptr_sd) {
			NDR_PULL_ALLOC(ndr, r->sd);
		} else {
			r->sd = NULL;
		}
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->hash_type));
		size_hash_0 = 64;
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->hash, size_hash_0));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->sd) {
			_mem_save_sd_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->sd, 0);
			NDR_CHECK(ndr_pull_security_descriptor(ndr, NDR_SCALARS|NDR_BUFFERS, r->sd));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sd_0, 0);
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_xattr_NTACL_Info(struct ndr_pull *ndr, int ndr_flags, union xattr_NTACL_Info *r)
{
	uint32_t level;
	uint16_t _level;
	TALLOC_CTX *_mem_save_sd_0;
	uint32_t _ptr_sd;
	TALLOC_CTX *_mem_save_sd_hs2_0;
	uint32_t _ptr_sd_hs2;
	TALLOC_CTX *_mem_save_sd_hs3_0;
	uint32_t _ptr_sd_hs3;
	TALLOC_CTX *_mem_save_sd_hs4_0;
	uint32_t _ptr_sd_hs4;
	level = ndr_pull_get_switch_value(ndr, r);
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_union_align(ndr, 5));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &_level));
		if (_level != level) {
			return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u for r at %s", _level, 0);
		}
		NDR_CHECK(ndr_pull_union_align(ndr, 5));
		switch (level) {
			case 1: {
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_sd));
				if (_ptr_sd) {
					NDR_PULL_ALLOC(ndr, r->sd);
				} else {
					r->sd = NULL;
				}
			break; }

			case 2: {
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_sd_hs2));
				if (_ptr_sd_hs2) {
					NDR_PULL_ALLOC(ndr, r->sd_hs2);
				} else {
					r->sd_hs2 = NULL;
				}
			break; }

			case 3: {
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_sd_hs3));
				if (_ptr_sd_hs3) {
					NDR_PULL_ALLOC(ndr, r->sd_hs3);
				} else {
					r->sd_hs3 = NULL;
				}
			break; }

			case 4: {
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_sd_hs4));
				if (_ptr_sd_hs4) {
					NDR_PULL_ALLOC(ndr, r->sd_hs4);
				} else {
					r->sd_hs4 = NULL;
				}
			break; }

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, 0);
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		switch (level) {
			case 1:
				if (r->sd) {
					_mem_save_sd_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->sd, 0);
					NDR_CHECK(ndr_pull_security_descriptor(ndr, NDR_SCALARS|NDR_BUFFERS, r->sd));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sd_0, 0);
				}
			break;

			case 2:
				if (r->sd_hs2) {
					_mem_save_sd_hs2_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->sd_hs2, 0);
					NDR_CHECK(ndr_pull_security_descriptor_hash_v2(ndr, NDR_SCALARS|NDR_BUFFERS, r->sd_hs2));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sd_hs2_0, 0);
				}
			break;

			case 3:
				if (r->sd_hs3) {
					_mem_save_sd_hs3_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->sd_hs3, 0);
					NDR_CHECK(ndr_pull_security_descriptor_hash_v3(ndr, NDR_SCALARS|NDR_BUFFERS, r->sd_hs3));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sd_hs3_0, 0);
				}
			break;

			case 4:
				if (r->sd_hs4) {
					_mem_save_sd_hs4_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->sd_hs4, 0);
					NDR_CHECK(ndr_pull_security_descriptor_hash_v4(ndr, NDR_SCALARS|NDR_BUFFERS, r->sd_hs4));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sd_hs4_0, 0);
				}
			break;

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, 0);
		}
	}
	return NDR_ERR_SUCCESS;
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