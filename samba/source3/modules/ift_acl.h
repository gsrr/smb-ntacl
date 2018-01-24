#include "../librpc/gen_ndr/idmap.h"

#define XATTR_SIZE 10000

/*
  copy a dom_sid structure
*/
void ift_dom_sid_dup(struct dom_sid *ret, struct dom_sid *dom_sid)
{
    DEBUG(0,("ret %s -> sid %s\n", sid_string_dbg(ret), sid_string_dbg(dom_sid)));
    int i;
    ret->sid_rev_num = dom_sid->sid_rev_num;
    ret->id_auth[0] = dom_sid->id_auth[0];
    ret->id_auth[1] = dom_sid->id_auth[1];
    ret->id_auth[2] = dom_sid->id_auth[2];
    ret->id_auth[3] = dom_sid->id_auth[3];
    ret->id_auth[4] = dom_sid->id_auth[4];
    ret->id_auth[5] = dom_sid->id_auth[5];
    ret->num_auths = dom_sid->num_auths;

    for (i=0;i<dom_sid->num_auths;i++) {
        ret->sub_auths[i] = dom_sid->sub_auths[i];
    }
}


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

int iftacl_get_permission(struct iftacl_sd* sd, vfs_handle_struct* handle, files_struct *fsp, const char* name)
{
    char value[XATTR_SIZE];
    int valueLen;
    become_root();
    if (fsp && fsp->fh->fd != -1) 
    {
        valueLen = SMB_VFS_FGETXATTR(fsp, "security.iftacl", value, XATTR_SIZE);
    } 
    else 
    {
        valueLen = SMB_VFS_GETXATTR(handle->conn, name, "security.iftacl", value, XATTR_SIZE);
    }
    //int valueLen = getxattr(fsp->fsp_name->base_name, "security.iftacl", value, XATTR_SIZE);
    unbecome_root();
    if (valueLen < 0) 
    {
        return valueLen;
    }
    int offset = 0;
    int owner = read_bytes(value, 4, &offset);
    int group = read_bytes(value, 4, &offset);
    int i = 0;
    sd->owner = owner;
    sd->group = group;
    sd->num_aces = read_bytes(value, 4, &offset);
    sd->aces = (struct iftacl_aces*)malloc(sizeof(struct iftacl_aces) * sd->num_aces);
    for( i = 0 ;i < sd->num_aces ; i++)
    {
        sd->aces[i].type = read_bytes(value, 1, &offset);
        sd->aces[i].flags = read_bytes(value, 1, &offset);
        sd->aces[i].access = read_bytes(value, 4, &offset);
        sd->aces[i].role = read_bytes(value, 1, &offset);
        sd->aces[i].uid = read_bytes(value, 4, &offset);
    }
    return 0;
}

int merge_ift_acl(struct security_descriptor* psd, vfs_handle_struct *handle, files_struct *fsp, const char* name)
{
    struct iftacl_sd sd;      
    struct dom_sid usid;
    struct dom_sid gsid;
    int ret;
    int i;
    DEBUG(0,("merge_ift_acl:start, %s\n", name));
    ret = iftacl_get_permission(&sd, handle, fsp, name);
    if(ret < 0)
    {
        DEBUG(0,("security.iftacl is not exist:%d\n", ret));
        return ret;
    }
    if(psd -> owner_sid)
    {
        uid_to_sid(&usid, sd.owner);
        talloc_free(psd->owner_sid);
        psd->owner_sid = dom_sid_dup(psd, &usid);
    }
    if(psd-> group_sid)
    {
        gid_to_sid(&gsid, sd.group);
        talloc_free(psd->group_sid);
        psd->group_sid = dom_sid_dup(psd, &gsid);
    }
    DEBUG(0,("uid %d -> sid %s -> sid %s\n", sd.owner, sid_string_dbg(&usid), sid_string_dbg(psd->owner_sid)));
    DEBUG(0,("uid %d -> sid %s -> sid %s\n", sd.group, sid_string_dbg(&gsid), sid_string_dbg(psd->group_sid)));
    /*
    ift_dom_sid_dup(psd->owner_sid, &usid);
    ift_dom_sid_dup(psd->group_sid, &gsid);
    */
    if(psd->dacl)
    {
        DEBUG(0,("show user:(psd.num_aces = %d, sd.num_aces=%d)\n", psd->dacl->num_aces, sd.num_aces));
        if(psd->dacl->num_aces != sd.num_aces)
        {
            DEBUG(0,("merge_ift_acl:number of psd and sd is not the same\n"));
            return;
        }
        int cnt = 0;
        for(i = 0 ; i < psd->dacl->num_aces ; i++)
        {
            DEBUG(0,("show user:(role = %d,role=%d)\n", sd.aces[i].role, sd.aces[i].uid));
            if(sd.aces[i].role != 101)
            {
                psd->dacl->aces[cnt].type = sd.aces[i].type;
                psd->dacl->aces[cnt].flags = sd.aces[i].flags;
                psd->dacl->aces[cnt].access_mask = sd.aces[i].access;
                psd->dacl->aces[cnt].trustee = psd->dacl->aces[i].trustee;
                cnt += 1;
            }
        }
        psd->dacl->num_aces = cnt;
        /*
        struct security_ace *aces;
        aces = talloc_array(psd, struct security_ace, cnt);
        int j = 0;
        for(i = 0 ; i < sd.num_aces ; i++)
        {
            if(sd.aces[i].role != 101)
            {
                aces[j].type = sd.aces[i].type;
                aces[j].flags = sd.aces[i].flags;
                aces[j].access_mask = sd.aces[i].access;
                aces[j].trustee = psd->dacl->aces[i].trustee;
                j += 1;
            }
        }
        talloc_free(psd->dacl->aces);
        psd->dacl->num_aces = cnt;
        psd->dacl->aces = aces;
        */
        free(sd.aces);
        DEBUG(0,("merge_ift_acl:end, %s\n", name));
    }
    else
    {
        DEBUG(0,("merge_ift_acl: dacl is null, %s\n", name));
    }
}

int write_bytes(char* blob, int value, int size, int* offset)
{
    int i = *offset;
    int end = *offset + size;
    if(size == 4)
    {
        blob[i] = (value >> 24) & 0xFF;
        blob[i + 1] = (value >> 16) & 0xFF;
        blob[i + 2] = (value >> 8) & 0xFF;
        blob[i + 3] = (value) & 0xFF;
    }
    else if(size == 1)
    {
        blob[i] = (value) & 0xFF;
    }
    *offset += size;
}

void convert_sd_to_iftblob(struct security_descriptor* psd, char* blob)
{
    DEBUG(0,("convert sd to iftblob\n"));
    int i;
    int offset = 0;
    struct unixid ownerid;
    struct unixid groupid;
    if(psd->owner_sid)
    {
        sids_to_unixids(psd->owner_sid, 1, &ownerid);
        DEBUG(0,("owner: sid %s -> uid %d, type:%d\n", sid_string_dbg(psd->owner_sid), ownerid.id, ownerid.type));
    }
    if(psd->group_sid)
    {
        sids_to_unixids(psd->group_sid, 1, &groupid);
        DEBUG(0,("group: sid %s -> uid %d, type:%d\n", sid_string_dbg(psd->group_sid), groupid.id, groupid.type));
    }
    write_bytes(blob, ownerid.id, 4, &offset);
    write_bytes(blob, groupid.id, 4, &offset);
    if(psd->dacl)
    {
        DEBUG(0,("num_aces:%d\n", psd->dacl->num_aces));
        write_bytes(blob, psd->dacl->num_aces, 4, &offset);
        for(i = 0 ; i < psd->dacl->num_aces ; i++)
        {
            struct unixid userid;
            write_bytes(blob, psd->dacl->aces[i].type, 1, &offset);
            write_bytes(blob, psd->dacl->aces[i].flags, 1, &offset);
            write_bytes(blob, psd->dacl->aces[i].access_mask, 4, &offset);
            if(!sids_to_unixids(&(psd->dacl->aces[i].trustee), 1, &userid))
            {
                DEBUG(0,("convert to unixid fail, aces:sid %s\n", sid_string_dbg(&(psd->dacl->aces[i].trustee))));
            } 
            else
            { 
                DEBUG(0,("aces:sid %s -> type : %d, uid: %d\n", sid_string_dbg(&(psd->dacl->aces[i].trustee)), userid.type, userid.id));
                if (userid.type == ID_TYPE_BOTH) {
                    write_bytes(blob, 1, 1, &offset);
                    write_bytes(blob, userid.id, 4, &offset);
                }
                else if (userid.type == ID_TYPE_UID) {
                    write_bytes(blob, 1, 1, &offset);
                    write_bytes(blob, userid.id, 4, &offset);
                }
                else if (userid.type == ID_TYPE_GID) {
                    write_bytes(blob, 2, 1, &offset);
                    write_bytes(blob, userid.id, 4, &offset);
                }
                else{
                    write_bytes(blob, 1, 1, &offset); // ignore
                    write_bytes(blob, 0, 4, &offset);
                }
            }
        }
    }
}

void ift_store_acl_blob(vfs_handle_struct *handle, files_struct *fsp, struct security_descriptor* psd)
{
    DEBUG(0,("ift store acl blob\n"));
    become_root();
    int ret = 0; 
    char *blob;
    int size = 4 * 3;
    if(psd->dacl)
    {
        size += 11 * psd->dacl->num_aces;
    }
    blob = malloc(sizeof(char) * size);
    convert_sd_to_iftblob(psd, blob);
    if (fsp->fh->fd != -1) 
    {
        ret = SMB_VFS_FSETXATTR(fsp, "security.iftacl", blob, size, 0);
    } 
    else 
    {
        ret = SMB_VFS_SETXATTR(fsp->conn, fsp->fsp_name->base_name, "security.iftacl", blob, size, 0);
    }
    free(blob);
    unbecome_root(); 
}

