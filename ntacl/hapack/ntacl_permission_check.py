import sys

IFT_ALLOW = 0
IFT_DENY = 1001

IFT_READ_DATA = 0x100001 
IFT_WRITE_DATA = 0x100002 
IFT_READ_PERM = 0x120000
IFT_CHANGE_PERM = 0x140000
IFT_CHANGE_OWNER = 0x180000

def permission_check(sids, sd, mask):
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

def check_owner(func):
    def wrap_func(sids, uid, sd):
        if sids[0] == str(sd.owner_sid):
            return 0
        else:
            return func(sids, uid, sd)
    return wrap_func

def getntacl(sids, uid, sd):
    return permission_check(sids, sd, IFT_READ_PERM)

@check_owner
def setntacl(sids, uid, sd):
    return permission_check(sids, sd, IFT_CHANGE_PERM)

@check_owner
def setowner(sids, uid, sd):
    return permission_check(sids, sd, IFT_CHANGE_OWNER)

def test_get_sids_from_uid(uid):
    print get_sids_from_uid(int(uid))

def main():
    func = getattr(sys.modules[__name__], sys.argv[1])
    func(*sys.argv[2:])


if __name__ == "__main__":
    main()
