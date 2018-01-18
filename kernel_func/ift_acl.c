#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/uidgid.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include "xattr.h"
#include "byteorder.h"

#define NDR_ERR_CODE_IS_SUCCESS(x) (x == NDR_ERR_SUCCESS)

#define NDR_CHECK(call) do { \
    enum ndr_err_code _status; \
    _status = call; \
    if (unlikely(!NDR_ERR_CODE_IS_SUCCESS(_status))) {  \
        return _status; \
    } \
} while (0)

#define NDR_BE(ndr) (unlikely(((ndr)->flags & (LIBNDR_FLAG_BIGENDIAN|LIBNDR_FLAG_LITTLE_ENDIAN)) == LIBNDR_FLAG_BIGENDIAN))

#define NDR_SVAL(ndr, ofs) (NDR_BE(ndr)?RSVAL(ndr->data,ofs):SVAL(ndr->data,ofs))

#define NDR_IVAL(ndr, ofs) (NDR_BE(ndr)?RIVAL(ndr->data,ofs):IVAL(ndr->data,ofs))

#define _array_size_chk(arr) 0
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

enum security_descriptor_revision
{
    SECURITY_DESCRIPTOR_REVISION_1=(int)(1)
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

enum security_acl_revision
{
    SECURITY_ACL_REVISION_NT4=(int)(2),
    SECURITY_ACL_REVISION_ADS=(int)(4)
};

struct dom_sid {
    uint8_t sid_rev_num;
    int8_t num_auths;/* [range(0,15)] */
    uint8_t id_auth[6];
    uint32_t sub_auths[15];
}/* [gensize,noprint,nopull,nopush,nosize,public] */;

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

struct acl_entry{
	int owner_sid;
	int group_sid;
	int num_aces;
	struct security_ace *aces;
};

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
        return NDR_ERR_BUFSIZE; \
    } \
} while(0)

#define NDR_PULL_NEED_BYTES(ndr, n) do { \
    if (unlikely((n) > ndr->data_size || ndr->offset + (n) > ndr->data_size)) { \
        if (ndr->flags & LIBNDR_FLAG_INCOMPLETE_BUFFER) { \
            uint32_t _available = ndr->data_size - ndr->offset; \
            uint32_t _missing = n - _available; \
            ndr->relative_highest_offset = _missing; \
        } \
        return NDR_ERR_BUFSIZE; \
    } \
} while(0)

size_t ascii_len_n(const char *src, size_t n)
{
    size_t len;

    len = strnlen(src, n);
    if (len+1 <= n) {
        len += 1;
    }

    return len;
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

enum ndr_err_code ndr_pull_union_align(struct ndr_pull *ndr, size_t size)
{
    /* MS-RPCE section 2.2.5.3.4.4 */
    if (ndr->flags & LIBNDR_FLAG_NDR64) {
        return ndr_pull_align(ndr, size);
    }
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_uint32(struct ndr_pull *ndr, int ndr_flags, uint32_t *v)
{
    NDR_PULL_ALIGN(ndr, 4);
    NDR_PULL_NEED_BYTES(ndr, 4);
    *v = NDR_IVAL(ndr, ndr->offset);
    ndr->offset += 4;
    return NDR_ERR_SUCCESS;
}


enum ndr_err_code ndr_pull_uint16(struct ndr_pull *ndr, int ndr_flags, uint16_t *v)
{
    NDR_PULL_ALIGN(ndr, 2);
    *v = NDR_SVAL(ndr, ndr->offset);
    ndr->offset += 2;
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_uint8(struct ndr_pull *ndr, int ndr_flags, uint8_t *v)
{
    NDR_PULL_NEED_BYTES(ndr, 1);
    *v = CVAL(ndr->data, ndr->offset);
    ndr->offset += 1;
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_int8(struct ndr_pull *ndr, int ndr_flags, int8_t *v)
{
    NDR_PULL_NEED_BYTES(ndr, 1);
    *v = (int8_t)CVAL(ndr->data, ndr->offset);
    ndr->offset += 1;
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
    if (!(ndr_flags & NDR_SCALARS)) {
        return NDR_ERR_SUCCESS;
    }
    return ndr_pull_bytes(ndr, data, n);
}

enum ndr_err_code ndr_pull_enum_uint8(struct ndr_pull *ndr, int ndr_flags, uint8_t *v)
{
    return ndr_pull_uint8(ndr, ndr_flags, v);
}

enum ndr_err_code ndr_pull_udlong(struct ndr_pull *ndr, int ndr_flags, uint64_t *v)
{
    NDR_PULL_ALIGN(ndr, 4);
    NDR_PULL_NEED_BYTES(ndr, 8);
    *v = NDR_IVAL(ndr, ndr->offset);
    *v |= (uint64_t)(NDR_IVAL(ndr, ndr->offset+4)) << 32;
    ndr->offset += 8;
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_NTTIME(struct ndr_pull *ndr, int ndr_flags, NTTIME *t)
{
    NDR_CHECK(ndr_pull_udlong(ndr, ndr_flags, t));
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

enum ndr_err_code ndr_pull_security_acl_revision(struct ndr_pull *ndr, int ndr_flags, enum security_acl_revision *r)
{
	uint16_t v;
	NDR_CHECK(ndr_pull_enum_uint1632(ndr, NDR_SCALARS, &v));
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
            return NDR_ERR_RANGE;
        }
        NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->id_auth, 6));
        ZERO_STRUCT(r->sub_auths);
        for (cntr_sub_auths_0 = 0; cntr_sub_auths_0 < r->num_auths; cntr_sub_auths_0++) {
            NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->sub_auths[cntr_sub_auths_0]));
        }
    }
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

        /*
        NDR_CHECK(ndr_pull_security_ace_object_ctr(ndr, NDR_SCALARS, &r->object));
        */
        NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, &r->trustee));

        size = ndr->offset - start_ofs;
        if (r->size < size) {
            return NDR_ERR_BUFSIZE;
        }
        pad = r->size - size;
        NDR_PULL_NEED_BYTES(ndr, pad);
        ndr->offset += pad;
    }
    if (ndr_flags & NDR_BUFFERS) {
        /*
        NDR_CHECK(ndr_pull_security_ace_object_ctr(ndr, NDR_BUFFERS, &r->object));
        */
    }
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_security_acl(struct ndr_pull *ndr, int ndr_flags, struct acl_entry *entries)
{
	enum security_acl_revision revision;
	uint16_t size;/* [value(ndr_size_security_acl(r,ndr->flags))] */
	uint32_t num_aces;/* [range(0,2000)] */
	int i = 0;
	NDR_CHECK(ndr_pull_align(ndr, 4));
	NDR_CHECK(ndr_pull_security_acl_revision(ndr, NDR_SCALARS, &revision));
	NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &size));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &num_aces));
	
	entries->num_aces = num_aces;
	entries->aces = (struct security_ace*) kmalloc(sizeof(struct security_ace) * num_aces, GFP_KERNEL);
	for(i = 0 ; i < num_aces ; i++)
	{
		NDR_CHECK(ndr_pull_security_ace(ndr, NDR_SCALARS, &(entries->aces[i])));
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code get_ndr_acl_entries(struct ndr_pull *ndr, int ndr_flags, struct acl_entry *entries)
{
	uint16_t level;
	uint16_t _level;
	uint32_t _ptr_sd_hs;
	uint32_t _ptr_sd;
	NTTIME time;
	uint32_t _flags_save_STRUCT;
	enum security_descriptor_revision revision;
	uint16_t type;
	uint32_t _ptr_owner_sid;
	uint32_t _ptr_group_sid;
	uint32_t _ptr_sacl;
	uint32_t _ptr_dacl;

	uint32_t _relative_save_offset;
	struct dom_sid owner_sid;
	struct dom_sid group_sid;

	ndr_pull_align(ndr, 5);
	ndr_pull_uint16(ndr, NDR_SCALARS, &level);

	NDR_CHECK(ndr_pull_union_align(ndr, 5));
	NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &_level));
	if (_level != level) {
		return NDR_ERR_BAD_SWITCH;
	}

	NDR_CHECK(ndr_pull_union_align(ndr, 5));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS,  &_ptr_sd_hs));

	NDR_CHECK(ndr_pull_align(ndr, 5));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_sd));

	ndr->offset += 2; /* hash_type */
	ndr->offset += 64; /* size_hash_0 */

	if(level == 4)
	{
		size_t conv_src_len = ascii_len_n((const char *)(ndr->data + ndr->offset), ndr->data_size - ndr->offset);
		ndr->offset += conv_src_len;
	}

	NDR_CHECK(ndr_pull_NTTIME(ndr, NDR_SCALARS, &time));
	ndr->offset += 64; /*size_sys_acl_hash_0*/
	NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	
	_flags_save_STRUCT = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_LITTLE_ENDIAN);
	NDR_CHECK(ndr_pull_align(ndr, 5));
	NDR_CHECK(ndr_pull_security_descriptor_revision(ndr, NDR_SCALARS, &revision));
	NDR_CHECK(ndr_pull_security_descriptor_type(ndr, NDR_SCALARS, &type));

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_owner_sid));

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_group_sid));

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_sacl));

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_dacl));

	NDR_CHECK(ndr_pull_trailer_align(ndr, 5));

	if (_ptr_owner_sid)
	{
		_relative_save_offset = ndr->offset;
		ndr->offset = _ptr_owner_sid; 
		NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, &owner_sid));
		if (ndr->offset > ndr->relative_highest_offset) {
			ndr->relative_highest_offset = ndr->offset;
		}
		ndr->offset = _relative_save_offset;
		entries->owner_sid = owner_sid.sub_auths[owner_sid.num_auths- 1];
	}

	if (_ptr_group_sid)
	{
		_relative_save_offset = ndr->offset;
		ndr->offset = _ptr_group_sid; 
		NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, &group_sid));
		if (ndr->offset > ndr->relative_highest_offset) {
			ndr->relative_highest_offset = ndr->offset;
		}
		ndr->offset = _relative_save_offset;
		entries->group_sid = group_sid.sub_auths[group_sid.num_auths- 1];
	}

	if (_ptr_dacl)
	{
		_relative_save_offset = ndr->offset;
		ndr->offset = _ptr_dacl; 
		ndr_pull_security_acl(ndr, NDR_SCALARS|NDR_BUFFERS, entries);

		if (ndr->offset > ndr->relative_highest_offset) {
			ndr->relative_highest_offset = ndr->offset;
		}
		ndr->offset = _relative_save_offset;
	}
    	return NDR_ERR_SUCCESS;

}

int He1(void)
{
	printk(KERN_INFO "..damon\n");
	return 0;
}

int ift_permission_check(struct acl_entry *entries, int mask)
{
	int i;
	int j;
	int perm_deny = 0;
	int find_entry = 0;
	int perm_allow = 0;
	kuid_t fsuid = current_fsuid();
	kgid_t fsgid = current_fsgid();
	printk(KERN_INFO "user uid:%d\n", fsuid.val);
	printk(KERN_INFO "group gid:%d\n", fsgid.val);
	printk(KERN_INFO "owner_sid:%d\n", entries->owner_sid);
	printk(KERN_INFO "group_sid:%d\n", entries->group_sid);
	
	/* check deny permission */
	for(i = 0 ; i < entries->num_aces ; i++)
	{
		int sid = entries->aces[i].trustee.sub_auths[entries->aces[i].trustee.num_auths - 1];
		int type = entries->aces[i].type;
		if(type != 1)
		{
			break;
		}
		printk(KERN_INFO "acl sid:%d\n", sid);
		printk(KERN_INFO "acl type:%d\n", type);
		printk(KERN_INFO "acl mask:access_mask:%d:%d\n", mask, entries->aces[i].access_mask);
		if(fsuid.val == sid)
		{
			perm_deny |= entries->aces[i].access_mask;
		}	
	}
	if((perm_deny & mask) != 0)
	{
		return -1; /* not allow */
	}
	

	/* check allow permission */
	for(j = i ; i < entries->num_aces ; i++)
	{
		int sid = entries->aces[i].trustee.sub_auths[entries->aces[i].trustee.num_auths - 1];
		printk(KERN_INFO "acl sid:%d\n", sid);
		printk(KERN_INFO "acl type:%d\n", entries->aces[i].type);
		printk(KERN_INFO "acl mask:access_mask:%d:%d\n", mask, entries->aces[i].access_mask);
		if(fsuid.val == sid)
		{
			find_entry = 1;
			perm_allow |= entries->aces[i].access_mask;
		}	
	}
	if(find_entry == 0)
	{
		return 0; /* check permission by posix_acl */
	}
	return  ~((perm_allow & mask) == mask);
}

/*
 * 1. create owner ,create group, everyone
 * 2. unix id
 * 3. group search (which group contain this user)
 *
 * */

/*
int ift_inode_permission(struct dentry* victim, int mask)
{
	int ret = 0;
	struct inode *inode = victim->d_inode;
	char *value;
	int error = 0;
	int value_len;
	struct acl_entry entries;
    	struct ndr_pull ndr;
	ndr.flags = 0;
	ndr.offset = 0;

	if(inode->i_op->getxattr != NULL)
	{
	
		value_len = inode->i_op->getxattr(victim, "security.NTACL", NULL, 0);
		if(value_len < 0)
		{
			return value_len;
		}
		value = kmalloc(sizeof(char) * (value_len + 1), GFP_KERNEL);
		memset(value, 0, value_len + 1);
		error = inode->i_op->getxattr(victim, "security.NTACL", value, value_len);
	    	ndr.data = value;
	    	ndr.data_size = value_len;    
	    	get_acl_entries(&ndr, NDR_SCALARS | NDR_BUFFERS, &entries);
		ret = ift_permission_check(&entries, mask);
		kfree(entries.aces);
		kfree(value);
		printk(KERN_INFO "permission check(0--> success, ~0--> fail):%d\n", ret);
	}
	return ret;
}
*/

/* Big endian */
int read_bytes(char* value, int size, int* offset)
{
    int num = 0;
    int i;
    for(i = 0 ; i < size ; i++)
    {
        num = num << 8;
        num |= (value[*offset + i] & 0xff);
    }
    *offset += size;
    return num;
}

void permission_combine(int *right, char flags, int access_mask, char role, int id, int owner, int group)
{
	kuid_t fsuid = current_fsuid();
	/*
	kgid_t fsgid = current_fsgid();
	struct cred *cred = current_cred();
	struct group_info *group_info = cred->group_info;
	*/
	
	printk(KERN_INFO "fsuid:%d\n", fsuid.val);
	printk(KERN_INFO "id:%d\n", id);
	printk(KERN_INFO "role:%d\n", role);

	if(role == 100) /* Ignore */
	{
		printk(KERN_INFO "Ignore\n");
		return;
	}

	if(role == 1) /* user */
	{
		if(fsuid.val == id)
		{
			printk(KERN_INFO "user match\n");
			*right |= access_mask;
		}
	}
	else if(role == 2) /* group */
	{
		kgid_t tgid = {id};
		if(in_group_p(tgid))
		{
			printk(KERN_INFO "group find\n");
			*right |= access_mask;
		}
	}
	else if(role == 3) /* Everyone */
	{
		printk(KERN_INFO "Everyone match\n");
		*right |= access_mask;
	}
	else if(role == 4) /* CO */
	{
		printk(KERN_INFO "create owner match\n");
		if(fsuid.val == owner)
		{
			*right |= access_mask;
		}
	}
}

int ift_permission_check2(char* value, int mask)
{
	int offset = 0;
	int owner = read_bytes(value, 4, &offset);
	int group = read_bytes(value, 4, &offset);
	int num = read_bytes(value, 4, &offset);
	int deny_right = 0;
	int allow_right = 0;
	int i;
	for(i = 0 ; i < num ; i++)
	{
		char type = read_bytes(value, 1, &offset);
		char flags = read_bytes(value, 1, &offset);
		int access_mask = read_bytes(value, 4, &offset);
		char role = read_bytes(value, 1, &offset);
		int id = read_bytes(value, 4, &offset);
		if(type == 0) /* allow */
		{
			permission_combine(&allow_right, flags, access_mask, role, id, owner, group);	
		}
		else if(type == 1) /* deny */
		{
			permission_combine(&deny_right, flags, access_mask, role, id, owner, group);	
		}
	}		

	printk(KERN_INFO "allow right:%d, deny right:%d\n", allow_right, deny_right);
	if((deny_right & mask) != 0)
	{
		return -1; /* not allow */
	}
	return  ~((allow_right & mask) == mask);
}

int ift_inode_permission(struct dentry* victim, int mask)
{
	int ret = 0;
	struct inode *inode = victim->d_inode;
	char *value;
	int error = 0;
	int value_len;

	if(inode->i_op->getxattr != NULL)
	{
	
		value_len = inode->i_op->getxattr(victim, "security.iftacl", NULL, 0);
		if(value_len < 0)
		{
			return value_len;
		}
		value = kmalloc(sizeof(char) * (value_len + 1), GFP_KERNEL);
		memset(value, 0, value_len + 1);
		error = inode->i_op->getxattr(victim, "security.iftacl", value, value_len);
		ret = ift_permission_check2(value, mask);
		kfree(value);
		printk(KERN_INFO "permission check(0--> success, ~0--> fail):%d\n", ret);
	}
	return ret;
}

EXPORT_SYMBOL(He1);
EXPORT_SYMBOL(ift_inode_permission);
