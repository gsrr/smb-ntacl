#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/uidgid.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <net/genetlink.h>
#include <linux/posix_acl.h>

#define XATTR_IFTACL_NAME	"security.iftacl"
#define XATTR_NTACL_NAME	"security.NTACL"

#define IFT_SUBFOLDER 0x02
#define IFT_SUBFILE 0x01

#define IFT_NTACL_READ   (0x000001 | 0x000008 | 0x000080 | 0x020000)
#define IFT_NTACL_WRITE  (0x000002 | 0x000004 | 0x000100 | 0x000010 | 0x040000)
#define IFT_NTACL_EXEC   0x000020

int ift_enable_flag = 0;

struct iftacl_aces
{
    char type;
    char flags;
    int access;
    char role;
    int uid;
};

struct iftacl_sd
{
    int owner;
    int group;
    int num_aces;
    struct iftacl_aces *aces;
};


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

	if(role == 100 || role == 101) /* Ignore and Not Inherit*/
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

int ift_permission_check(char* value, int mask)
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

	printk(KERN_INFO "mask:%d, allow right:%d, deny right:%d\n", mask, allow_right, deny_right);
	if((deny_right & mask) != 0)
	{
		return -1; /* not allow */
	}
	return (allow_right & mask) == mask ? 0 : -1;
}

int ift_inode_permission(struct inode* victim_inode, int mask)
{
	int ret = 0;
	char *value;
	int error = 0;
	int value_len;
	struct dentry *victim_dentry = NULL;

	/*
	if (ift_enable_flag == 0 || current_cred()->uid.val == 0)
	    return 0;
	*/
	if (current_cred()->uid.val == 0) {
	    return 0;
	}
	victim_dentry = d_obtain_alias(victim_inode);
	
	if(victim_inode->i_op->getxattr != NULL)
	{
	
		value_len = victim_inode->i_op->getxattr(victim_dentry, XATTR_IFTACL_NAME, NULL, 0);
		if(value_len < 0)
		{
			return value_len;
		}
		value = kmalloc(sizeof(char) * (value_len + 1), GFP_KERNEL);
		memset(value, 0, value_len + 1);
		error = victim_inode->i_op->getxattr(victim_dentry, XATTR_IFTACL_NAME, value, value_len);
		ret = ift_permission_check(value, mask);
		kfree(value);
		printk(KERN_INFO "permission check(0--> success, ~0--> fail):%d\n", ret);
	}
	return ret;
}

void iftacl_push_to_blob(char* blob, void *value, int size, int *offset)
{
    int i = *offset;
    int* ivalue = (int*) value;
    if(size == 4)
    {
        blob[i] = (*ivalue >> 24) & 0xFF;
        blob[i + 1] = (*ivalue >> 16) & 0xFF;
        blob[i + 2] = (*ivalue >> 8) & 0xFF;
        blob[i + 3] = (*ivalue) & 0xFF;
    }
    else if(size == 1)
    {
        blob[i] = (*ivalue) & 0xFF;
    }
    *offset += size;
}

void iftacl_sd_to_blob(char* blob, struct iftacl_sd *iftsd)
{
    int offset = 0;
    int i = 0;
    iftacl_push_to_blob(blob, &(iftsd->owner), 4, &offset);
    iftacl_push_to_blob(blob, &(iftsd->group), 4, &offset);
    iftacl_push_to_blob(blob, &(iftsd->num_aces), 4, &offset);
    for(i = 0 ; i < iftsd->num_aces ; i++)
    {
            iftacl_push_to_blob(blob, &(iftsd->aces[i].type), 1, &offset);
            iftacl_push_to_blob(blob, &(iftsd->aces[i].flags), 1, &offset);
            iftacl_push_to_blob(blob, &(iftsd->aces[i].access), 4, &offset);
            iftacl_push_to_blob(blob, &(iftsd->aces[i].role), 1, &offset);
            iftacl_push_to_blob(blob, &(iftsd->aces[i].uid), 4, &offset);
    }
}


int get_blob_len(int num_aces)
{
	int blob_len = 4 * 3 + 11 * num_aces;
	return blob_len;	
}

int iftacl_store_blob(struct dentry* victim, struct iftacl_sd* iftsd)
{
	int ret = 0;
	char* blob;
	struct inode *inode = victim->d_inode;
	int blob_len = get_blob_len(iftsd->num_aces);
	blob = (char*)kmalloc(sizeof(char) * blob_len, GFP_KERNEL);
	iftacl_sd_to_blob(blob, iftsd);
    ret = inode->i_op->setxattr(victim, XATTR_IFTACL_NAME, blob, blob_len, 0);
	kfree(blob);	
	return ret;
}

int iftacl_get_permission(struct dentry* victim, struct iftacl_sd *iftsd)
{
	int error;
	int offset = 0;
	struct inode *inode = victim->d_inode;
	char* value;
	int value_len;
	int i;
	value_len = inode->i_op->getxattr(victim, XATTR_IFTACL_NAME, NULL, 0);
	if(value_len < 0)
	{
		return value_len;
	}
	value = kmalloc(sizeof(char) * (value_len + 1), GFP_KERNEL);
	memset(value, 0, value_len + 1);
	error = inode->i_op->getxattr(victim, XATTR_IFTACL_NAME, value, value_len);
	if(error <= 0)
	{
		kfree(value);	
		return -1;
	}
	iftsd->owner = read_bytes(value, 4, &offset);
	iftsd->group = read_bytes(value, 4, &offset);
	iftsd->num_aces = read_bytes(value, 4, &offset);
	iftsd->aces = (struct iftacl_aces*)kmalloc(sizeof(struct iftacl_aces) * iftsd->num_aces, GFP_KERNEL);
	for( i = 0 ;i < iftsd->num_aces ; i++)
	{
		iftsd->aces[i].type = read_bytes(value, 1, &offset);
		iftsd->aces[i].flags = read_bytes(value, 1, &offset);
		iftsd->aces[i].access = read_bytes(value, 4, &offset);
		iftsd->aces[i].role = read_bytes(value, 1, &offset);
		iftsd->aces[i].uid = read_bytes(value, 4, &offset);
	}
	kfree(value);	
	return 0;	
}

/*
 * The acl will retain (owner, group, everyone) after chmod.
 */
int iftacl_chmod(struct inode* victim_inode, int *mask)
{
	int ret = 0;
	struct dentry* victim_dentry = NULL;
	victim_dentry = d_obtain_alias(victim_inode);

	victim_inode->i_op->removexattr(victim_dentry, "system.posix_acl_access");
	victim_inode->i_op->removexattr(victim_dentry, XATTR_IFTACL_NAME);
	victim_inode->i_op->removexattr(victim_dentry, XATTR_NTACL_NAME);
	return ret;
}

/*
 * Change owner id of security.iftacl
 */
int iftacl_chown(struct inode *victim_inode, int uid)
{
	int ret = 0;
	int error;
	struct iftacl_sd iftsd;
	struct dentry *victim_dentry = NULL;

	victim_dentry = d_obtain_alias(victim_inode);
	
	if(victim_inode->i_op->getxattr != NULL)
	{
		error = iftacl_get_permission(victim_dentry, &iftsd);
		if(error != 0)
		{
			return error;
		}
		iftsd.owner = uid;
		ret = iftacl_store_blob(victim_dentry,  &iftsd);
		kfree(iftsd.aces);
	}
	return ret;
}

void ntacl_to_posix_acl(struct posix_acl* acl, int idx, char type, int access)
{
        if((access & IFT_NTACL_READ) != 0)
        {
            if(type == 0)
            {
                acl->a_entries[idx].e_perm |= ACL_READ;
            }
            else
            {
                acl->a_entries[idx].e_perm &= ~ACL_READ;
            }
        }

        if((access & IFT_NTACL_WRITE) != 0)
        {
            if(type == 0)
            {
                acl->a_entries[idx].e_perm |= ACL_WRITE;
            }
            else
            {
                acl->a_entries[idx].e_perm &= ~ACL_WRITE;
            }

        }
        if((access & IFT_NTACL_EXEC) != 0)
        {
            if(type == 0)
            {
                acl->a_entries[idx].e_perm |=  ACL_EXECUTE;
            }
            else
            {
                acl->a_entries[idx].e_perm &=  ~ACL_EXECUTE;
            }
        }

}

int find_acl_user_entry(struct posix_acl *acl, int *cnt, char role, int id)
{
	int j;
    for(j = 0 ; j < *cnt ; j++)
    {
			if(acl->a_entries[j].e_tag == ACL_USER && acl->a_entries[j].e_uid.val == id)
			{
				return j;
			}
    }
	acl->a_entries[j].e_tag = ACL_USER;
	acl->a_entries[j].e_uid.val = id;
	*cnt += 1;
	return j;	
}

int find_acl_group_entry(struct posix_acl *acl, int *cnt, char role, int id)
{
	int j;
    for(j = 0 ; j < *cnt ; j++)
    {
			if(acl->a_entries[j].e_tag == ACL_GROUP && acl->a_entries[j].e_gid.val == id)
			{
				return j;
			}
    }
	acl->a_entries[j].e_tag = ACL_GROUP;
	acl->a_entries[j].e_gid.val = id;
	*cnt += 1;
	return j;	
}

void combine_acl(struct iftacl_sd *iftsd, int i, struct posix_acl *acl, int *cnt)
{
    char type = iftsd->aces[i].type;
    char role = iftsd->aces[i].role;
    int id = iftsd->aces[i].uid;
    int access = iftsd->aces[i].access;
	int j = -1;

	if(role == 100 || role == 101) /* Ignore role == 100 */
	{
		return;
	}
	
	if(role == 1)
	{
		j = find_acl_user_entry(acl, cnt, role, id);
	}
	else if(role == 2)
	{
		j = find_acl_group_entry(acl, cnt, role, id);
	}
	
	if(j != -1)
		ntacl_to_posix_acl(acl, j, type, access);
}

int inherit_require_entries(struct posix_acl *acl)
{
	int i;
	int cnt = 0;
	int require_tag = (ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_OTHER | ACL_MASK);
	for(i = 0 ; i < acl->a_count ; i++)
	{
		int e_tag = acl->a_entries[i].e_tag;
		if((e_tag & require_tag)!= 0)
		{
			acl->a_entries[cnt].e_tag = acl->a_entries[i].e_tag;
			acl->a_entries[cnt].e_perm = acl->a_entries[i].e_perm;
			acl->a_entries[cnt].e_uid = acl->a_entries[i].e_uid;
			cnt += 1;
		}
	}
	return cnt;	
}

int iftacl_inherit_child(struct dentry *victim, struct iftacl_sd *iftsd, struct posix_acl *acl, int iflag)
{
	int ret = 0;
	int cnt = 0;
	int i = 0;

	cnt += inherit_require_entries(acl);
	for(i = iftsd->num_aces - 1 ; i > -1 ; i--)
	{
		char af = iftsd->aces[i].flags;
		if((af & iflag) == 0)
		{
			iftsd->aces[i].role = 101; /*Not inherit*/
		}
		else
		{
			combine_acl(iftsd, i, acl, &cnt);
		}
	}
	acl->a_count = cnt;
	ret = iftacl_store_blob(victim,  iftsd);
	return ret;
}

int iftacl_inherit(struct dentry *pvictim, struct inode *inode_cvictim, struct posix_acl *acl)
{
	int ret = 0;
	int error;
	struct inode *pinode = pvictim->d_inode;
	struct dentry *dentry_cvictim = NULL;
	struct iftacl_sd iftsd;
	dentry_cvictim = d_obtain_alias(inode_cvictim);
	if(pinode->i_op->getxattr != NULL)
	{
		error = iftacl_get_permission(pvictim, &iftsd);
		if(error)
		{
			return error;
		}
		if(S_ISDIR(inode_cvictim->i_mode))
		{
			ret = iftacl_inherit_child(dentry_cvictim, &iftsd, acl, IFT_SUBFOLDER);
		}
		else
		{
			ret = iftacl_inherit_child(dentry_cvictim, &iftsd, acl, IFT_SUBFILE);	
		}
		kfree(iftsd.aces);
	}
	return ret;
}

EXPORT_SYMBOL(ift_inode_permission);
EXPORT_SYMBOL(iftacl_chmod);
EXPORT_SYMBOL(iftacl_chown);
EXPORT_SYMBOL(iftacl_inherit);

/*
static void ift_enable(struct sk_buff *skb, struct genl_info *info)
{
    printk(KERN_INFO "++++ift_enable+++\n");
    ift_enable_flag = 1;
}

enum attributes {
    ATTR_DUMMY,
    ATTR_ENABLE,
    __ATTR_MAX,
};

static struct genl_family ift_family = {
    .id = GENL_ID_GENERATE,
    .hdrsize = 0,
    .name = "IFT",
    .version = 1,
    .maxattr = __ATTR_MAX, 
};

static struct nla_policy ift_policy[] = {
    [ATTR_ENABLE] = {.type = NLA_U32, },
};
    
static struct genl_ops ift_ops[] = {
    {
	.cmd = ATTR_ENABLE,
	.flags = 0,
	.policy = ift_policy,
	.doit = ift_enable,
	.dumpit = NULL,
    }
};
    
static int __init ift_init(void) {
    int ret = 0;
    ret = genl_register_family_with_ops(&ift_family, ift_ops);
    if(ret != 0) {
	printk("++++ift-fail-registerFamily++++\n");
    }
    return ret;
}

static void __exit ift_exit(void) {
    int ret;
    ret = genl_unregister_family(&ift_family);
    if(ret !=0) {
	printk("++++ift-fail-Unregisterfamily+++\n");
    }
    //return ret;
}


module_init(ift_init);
module_exit(ift_exit);
MODULE_LICENSE("GPL");
*/
