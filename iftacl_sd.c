#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define XATTR_SIZE 10000

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

void test_iftacl()
{
    char value[XATTR_SIZE];
    int valueLen = getxattr("/tmp", "security.iftacl", value, XATTR_SIZE);
    int i;
    int offset = 0;
    int owner = read_bytes(value, 4, &offset);
    int group = read_bytes(value, 4, &offset);
    int num = read_bytes(value, 4, &offset);
    printf("owner:%d\n", owner);
    printf("group:%d\n", group);
    printf("num:%d\n", num);
    for(i = 0 ; i < num ; i++)
    {
            printf("--------------\n");
            char type = read_bytes(value, 1, &offset);
            char flags = read_bytes(value, 1, &offset);
            int access = read_bytes(value, 4, &offset);
            char role = read_bytes(value, 1, &offset);
            int uid = read_bytes(value, 4, &offset);
            printf("type:%d\n", type);
            printf("flags:%d\n", flags);
            printf("access:%d\n", access);
            printf("role:%d\n", role);
            printf("uid:%d\n", uid);
        
    }
}

void iftacl_push_to_blob(char* blob, void *value, int size, int *offset)
{
    int i = *offset;
    int end = *offset + size;
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

void iftacl_sd_to_blob(char* blob, struct iftacl_sd *sd)
{
    int offset = 0;
    int i = 0;
    printf("owner:%d\n", sd->owner); 
    iftacl_push_to_blob(blob, &(sd->owner), 4, &offset);
    printf("group:%d\n", sd->group); 
    iftacl_push_to_blob(blob, &(sd->group), 4, &offset);
    printf("nums:%d\n", sd->num_aces); 
    iftacl_push_to_blob(blob, &(sd->num_aces), 4, &offset);
    for(i = 0 ; i < sd->num_aces ; i++)
    {
            iftacl_push_to_blob(blob, &(sd->aces[i].type), 1, &offset);
            iftacl_push_to_blob(blob, &(sd->aces[i].flags), 1, &offset);
            iftacl_push_to_blob(blob, &(sd->aces[i].access), 4, &offset);
            iftacl_push_to_blob(blob, &(sd->aces[i].role), 1, &offset);
            iftacl_push_to_blob(blob, &(sd->aces[i].uid), 4, &offset);
    }
}

void iftacl_store_blob(char* path, char* blob, int size)
{
    setxattr(path, "security.iftacl", blob, size, 0); 
}

void test_iftacl_chmod()
{
    char value[XATTR_SIZE];
    int valueLen = getxattr("/tmp", "security.iftacl", value, XATTR_SIZE);
    int offset = 0;
    int owner = read_bytes(value, 4, &offset);
    int group = read_bytes(value, 4, &offset);
    struct iftacl_sd sd;
    char* blob;
    int i = 0;
    sd.owner = owner;
    sd.group = group;
    sd.num_aces = 3;
    sd.aces = (struct iftacl_aces*)malloc(sizeof(struct iftacl_aces) * 3);
    for( i = 0 ;i < 3 ; i++)
    {
        sd.aces[i].type = 0;
        sd.aces[i].flags = 0;
        sd.aces[i].access = 2032127;
        sd.aces[i].role = (i + 1) % 3 + 3; /* 3->others, 4->co, 5->cg*/
        sd.aces[i].uid = 0;
    }
    int length = 4 * 3 + sizeof(struct iftacl_aces) * sd.num_aces;
    printf("length : %d\n", length);
    blob = (char*)malloc(sizeof(char) * length);
    iftacl_sd_to_blob(blob, &sd);    
    for( i = 0 ; i < length ; i++)
    {
        printf("%x,", blob[i]);
    }
    printf("\n----------\n");
    iftacl_store_blob("/tmp",  blob, length);
    removexattr("/tmp", "system.posix_acl_access");
    free(sd.aces);
    free(blob);
}

void test_iftacl_chown()
{
    char value[XATTR_SIZE];
    int valueLen = getxattr("/tmp", "security.iftacl", value, XATTR_SIZE);
    int offset = 0;
    int owner = read_bytes(value, 4, &offset);
    int group = read_bytes(value, 4, &offset);
    struct iftacl_sd sd;
    char* blob;
    int i = 0;
    sd.owner = 1000;
    sd.group = group;
    sd.num_aces = read_bytes(value, 4, &offset);
    sd.aces = (struct iftacl_aces*)malloc(sizeof(struct iftacl_aces) * sd.num_aces);
    for( i = 0 ;i < sd.num_aces ; i++)
    {
        sd.aces[i].type = read_bytes(value, 1, &offset);
        sd.aces[i].flags = read_bytes(value, 1, &offset);
        sd.aces[i].access = read_bytes(value, 4, &offset);
        sd.aces[i].role = read_bytes(value, 1, &offset);
        sd.aces[i].uid = read_bytes(value, 4, &offset);
    }
    int length = 4 * 3 + sizeof(struct iftacl_aces) * sd.num_aces;
    printf("length : %d\n", length);
    blob = (char*)malloc(sizeof(char) * length);
    iftacl_sd_to_blob(blob, &sd);    
    for( i = 0 ; i < length ; i++)
    {
        printf("%x,", blob[i]);
    }
    printf("\n----------\n");
    iftacl_store_blob("/tmp",  blob, length);
    removexattr("/tmp", "system.posix_acl_access");
    free(sd.aces);
    free(blob);
}


void iftacl_get_permission(struct iftacl_sd* sd)
{
    char value[XATTR_SIZE];
    int valueLen = getxattr("/tmp", "security.iftacl", value, XATTR_SIZE);
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
    
}

struct ift_pacl
{
    int type;
    int id;
    int perm;
};

/*
List folders/READ data         0x100001 
Create files/Write data        0x100002
Create folders/Append data     0x100004
Read extended attributes       0x100008
Write attribute                0x100100
Write extended attribute       0x100010
Traverse folders/execute files 0x100020
Delete subfolders and files    0x100040
READ Attribute                 0x100080
Delete                         0x110000
Read permission                0x120000
Change permission          0x140000
take owner                 0x180000
*/

#define IFT_NTACL_READ   0x000001 | 0x000008 | 0x000080 | 0x020000
#define IFT_NTACL_WRITE  0x000002 | 0x000004 | 0x000100 | 0x000010 | 0x040000
#define IFT_NTACL_EXEC   0x000020

#define IFT_POSIX_READ  0x04
#define IFT_POSIX_WRITE 0x02
#define IFT_POSIX_EXEC  0x01


void ntacl_to_posix_acl(struct ift_pacl* pacl, int idx, char type, int access)
{
        if((access & IFT_NTACL_READ) != 0)
        {
            if(type == 0)
            {
                pacl[idx].perm |= IFT_POSIX_READ;
            } 
            else
            {
                pacl[idx].perm &= ~IFT_POSIX_READ;
            }
        }

        if((access & IFT_NTACL_WRITE) != 0)
        {
            if(type == 0)
            {
                pacl[idx].perm |= IFT_POSIX_WRITE; 
            } 
            else
            {
                pacl[idx].perm &= ~IFT_POSIX_WRITE; 
            }
            
        }
        if((access & IFT_NTACL_EXEC) != 0)
        {
            if(type == 0)
            {
                pacl[idx].perm |=  IFT_POSIX_EXEC;
            } 
            else
            {
                pacl[idx].perm &=  ~IFT_POSIX_EXEC;
            }
        }
    
}

void combine_acl(struct iftacl_sd* sd, int i, struct ift_pacl* pacl, int* cnt)
{
    char type = sd->aces[i].type;
    char role = sd->aces[i].role;
    int id = sd->aces[i].uid;
    int access = sd->aces[i].access;
    int j;
    int find = 0;
    for(j = 0 ; j < *cnt ; j++)
    {
        if(pacl[j].type == role && pacl[j].id == id)
        {
            find = 1;
            break;
        }
    }
    if(find == 0)
    {
        pacl[*cnt].type = role;
        pacl[*cnt].id = id;
        ntacl_to_posix_acl(pacl, j, type, access);
        *cnt += 1;
    }
    else
    {
        ntacl_to_posix_acl(pacl, j, type, access);
    } 
}

void test_iftacl_inherit()
{
    struct iftacl_sd sd;
    char* blob;
    int i;
    iftacl_get_permission(&sd);
    struct ift_pacl* pacl = (struct ift_pacl*)malloc(sizeof(struct ift_pacl) * sd.num_aces);
    int cnt = 0; 
    for(i = sd.num_aces - 1 ; i > -1 ; i--)
    {
        int af = sd.aces[i].flags;
        printf("af:%d\n", af);
        if((af & 0x02) == 0)
        {
            sd.aces[i].role = 101;
        }
        else
        {
            combine_acl(&sd, i, pacl, &cnt);
        }
    }
    for(i = 0 ; i < cnt ; i++)
    {
            printf("type : %d\n", pacl[i].type);
            printf("id : %d\n", pacl[i].id);
            printf("perm : %d\n", pacl[i].perm);
            printf("-----------------------\n");
    }
    int length = 4 * 3 + sizeof(struct iftacl_aces) * sd.num_aces;
    printf("length : %d\n", length);
    blob = (char*)malloc(sizeof(char) * length);
    iftacl_sd_to_blob(blob, &sd);    
    iftacl_store_blob("/tmp",  blob, length);
    free(sd.aces);
    free(blob);
    free(pacl);
}

int main(int argc, char **argv) 
{
    test_iftacl_inherit();
    test_iftacl();
    /*
    test_iftacl_chmod();
    test_iftacl_chown();
    test_iftacl_chmod();
    DATA_BLOB blob;
    char value[XATTR_SIZE];
    get_blob_from_path(&blob, value, argv[1]);

    struct ndr_pull ndr;

    ndr.data = blob.data;
    ndr.data_size = blob.length;    

    * ndr_pull_xattr_NTACL(&ndr, NDR_SCALARS|NDR_BUFFERS, &xacl); 
    get_acl_entries(&ndr, NDR_SCALARS | NDR_BUFFERS);
    */
    return 0;
}
