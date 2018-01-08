import sys
import grp
import pwd
import smb_ntacl

IFT_ALLOW = 0
IFT_DENY = 1001

IFT_READ_DATA = 0x100001 
IFT_WRITE_DATA = 0x100002 
IFT_READ_PERM = 0x120000
IFT_CHANGE_PERM = 0x140000
IFT_CHANGE_OWNER = 0x180000

def permission_check(sids, path, mask):
    sd = smb_ntacl.getntacl(path)
    st = 0
    deny_right = 0
    for i in xrange(st, len(sd.dacl.aces)):
        ace = sd.dacl.aces[i]
        if ace.type == 0:
            break
        
        if str(ace.trustee) in sids:
            deny_right |= ace.access_mask 
        st += 1
    if mask & deny_right != 0:
        return IFT_DENY

    allow_right = 0 
    for i in xrange(st, len(sd.dacl.aces)):
        ace = sd.dacl.aces[i]
        if str(ace.trustee) in sids:
            allow_right |= ace.access_mask

    if (mask & allow_right) == mask:
        return IFT_ALLOW
    return IFT_DENY

def get_sids_from_uid(nuid):
    uinfo = pwd.getpwuid(nuid) 
    gids = [uinfo.pw_gid]
    gids.extend([g.gr_gid for g in grp.getgrall() if uinfo.pw_name in g.gr_mem]) 
    sids = [smb_ntacl.uid_to_sid(nuid)]
    for gid in gids:
        sids.append(smb_ntacl.gid_to_sid(gid))
    return sids

def permission_check_api(uid, path, mask):
    sids = get_sids_from_uid(int(uid))
    print permission_check(sids, path, mask)
    
def getntacl(uid, path):
    sids = get_sids_from_uid(int(uid))
    print permission_check(sids, path, IFT_READ_PERM)

def setntacl(uid, path):
    sids = get_sids_from_uid(int(uid))
    print permission_check(sids, path, IFT_CHANGE_PERM)

def setowner(uid, path):
    sids = get_sids_from_uid(int(uid))
    print permission_check(sids, path, IFT_CHANGE_OWNER)

def main():
    func = getattr(sys.modules[__name__], sys.argv[1])
    func(*sys.argv[2:])


if __name__ == "__main__":
    main()
