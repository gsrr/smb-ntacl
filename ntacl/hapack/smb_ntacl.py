# getntacl and setntacl script
import sys
import os
import copy
import commands
import pwd
import traceback
import iftsmb
import ntacl_permission_check
import array
import struct
from samba.samba3 import param as s3param
from samba.dcerpc import security
from samba.samba3 import smbd, passdb

def get_lp(conf):
    lp = s3param.get_context()
    lp.load(conf)
    return lp

def get_pdb_local(conf):
    lp = get_lp(conf)
    lp.set("passdb backend", 'tdbsam')
    pdb = passdb.PDB(lp.get('passdb backend'))
    return pdb

def get_pdb(conf):
    lp = get_lp(conf)
    pdb = passdb.PDB(lp.get('passdb backend'))
    return pdb

def is_uid_local(uid):
    try:
        pdb = get_pdb_local("/etc/samba/smb.conf.default")
        sid = pdb.uid_to_sid(uid)    
        return str(sid)
    except:
        return None

def uid_to_sid_winbind(uid):
    #sid = commands.getoutput("wbinfo -U %d"%uid).strip() #0.092ms/1, 0.825/100
    sid = iftsmb.wb_uid_to_sid(uid) # 0.082ms/1, 0.093ms/100
    if "S-1-5-21" in sid: 
        return sid    
    return None

def uid_to_sid_ldap(uid):
    try:
        pdb = get_pdb("/etc/samba/smb.conf")
        sid = pdb.uid_to_sid(int(uid))    
        return str(sid)
    except:
        return None

def is_uid_domain(uid):
    lp = get_lp("/etc/samba/smb.conf")
    if len(lp.get("realm")) != 0:
        return uid_to_sid_winbind(uid)
    elif "ldapsam" in lp.get("passdb backend"):
        return uid_to_sid_ldap(uid)
    else:
        return None

def is_uid_unix(uid):
    return "S-1-22-1-%d"%uid

def execmds(cmds, *args):
    for cmd in cmds:
        ret = cmd(*args)
        if ret != None:
            return ret
 
def uid_to_sid(uid):
    '''
        uid : int
    '''
    cmds = [
        is_uid_local,
        is_uid_domain,
        is_uid_unix,
    ]
    return execmds(cmds, uid)

def is_gid_local(gid):
    try:
        pdb = get_pdb_local("/etc/samba/smb.conf")
        sid = pdb.gid_to_sid(int(gid))    
        return str(sid)
    except:
        return None

def gid_to_sid_winbind(gid):
    #sid = commands.getoutput("wbinfo -G %d"%gid).strip() # 0.093ms
    sid = iftsmb.wb_gid_to_sid(gid) #0.082ms
    if "S-1-5-21" in sid: 
        return sid    
    return None

def gid_to_sid_ldap(gid):
    try:
        pdb = get_pdb("/etc/samba/smb.conf")
        sid = pdb.gid_to_sid(int(gid))    
        return str(sid)
    except:
        return None

def is_gid_domain(gid):
    lp = get_lp("/etc/samba/smb.conf")
    if len(lp.get("realm")) != 0:
        return gid_to_sid_winbind(gid)
    elif "ldapsam" in lp.get("passdb backend"):
        return gid_to_sid_ldap(gid)
    else:
        return None

def is_gid_unix(gid):
    return "S-1-22-2-%d"%gid

def gid_to_sid(gid):
    '''
        gid : int
    '''
    cmds = [
        is_gid_local,
        is_gid_domain,
        is_gid_unix,
    ]
    return execmds(cmds, gid)

class SmbDefine:
    def __init__(self):
        pass

    @staticmethod
    def map_user(sid):
        User = {
            'S-1-1-0' : 'WD',
            'S-1-3-0' : 'CO',
            'S-1-3-1' : 'CG',
        }
        return User.get(sid, sid)

    @staticmethod
    def uid_to_sid(uid):
        User = {
            'WD' : 'S-1-1-0',
            'CO' : 'S-1-3-0',
            'CG' : 'S-1-3-1',
        }
        if User.get(uid) != None:
            return User[uid]
        else:
            tuid = uid[0]
            nuid = uid[1:] 
            if tuid == "u":
                return uid_to_sid(int(nuid))
            elif tuid == 'g':
                return gid_to_sid(int(nuid))
            return uid
          
def is_sid_local(sid):
    try:
        pdb = get_pdb_local("/etc/samba/smb.conf")
        uinfo = pdb.sid_to_id(security.dom_sid(sid))    
        return uinfo
    except:
        return None
    

def sid_to_uid_winbind(sid):
    uid = commands.getoutput("wbinfo -S %s"%sid).strip()
    if "WBC_ERR_DOMAIN_NOT_FOUND" in uid:
        return (sid, 1)
    return (uid, 1)

def sid_to_uid_ldap(sid):
    try:
        pdb = get_pdb("/etc/samba/smb.conf")
        uinfo = pdb.sid_to_id(security.dom_sid(sid))    
        return uinfo
    except:
        return (sid, 1)
    
def is_sid_domain(sid):
    lp = get_lp("/etc/samba/smb.conf")
    if len(lp.get("realm")) != 0:
        return sid_to_uid_winbind(sid)
    elif "ldapsam" in lp.get("passdb backend"):
        return sid_to_uid_ldap(sid)
    else:
        return (sid, 1)

def is_sid_special(sid):
    ssid = {
        'S-1-1-0' : 'WD',
        'S-1-3-0' : 'CO',
        'S-1-3-1' : 'CG',
    }    
    if ssid.has_key(sid):
        return (ssid[sid], 3)
    elif "S-1-22-1" in sid:
        return (sid.split("-")[-1], 1)
    elif "S-1-22-2" in sid:
        return (sid.split("-")[-1], 2)
    else:
        return None

def sid_to_uid(sid):
    cmds = [
        is_sid_special,
        is_sid_local,
        is_sid_domain,
    ]
    return execmds(cmds, sid)

def _getntacl(path):
    s3conf = s3param.get_context()
    s3conf.load("/etc/samba/smb.conf")
    sd = smbd.get_nt_acl(path, security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_SACL, service=None)
    return sd

def get_sids_from_uid(uid):
    uinfo = pwd.getpwuid(uid) 
    ngroup, gids = iftsmb.get_uid_groups(uid)
    sids = [uid_to_sid(uid)]
    for i in xrange(ngroup):
        sids.append(gid_to_sid(gids[i]))
    return sids

def permission_check_api(path, uid, mask):
    sids = get_sids_from_uid(int(uid))
    sd = _getntacl(path)
    print ntacl_permission_check.permission_check(sids, sd, int(mask))


def permission_check(op):
    def inner_func(func):
        def wrap_func(*args):
            path = args[0]
            ck_uid = args[1]
            if ck_uid == 0:
                return func(*args)
            else:
                sd = _getntacl(path)
                try:
                    sids = get_sids_from_uid(ck_uid)
                except:
                    print traceback.format_exc()
                    return {'status' : -1, 'msg' : 'can not find user'}
                ck_func = getattr(sys.modules["ntacl_permission_check"], op)
                ret = ck_func(sids, ck_uid, sd)
                if ret == 0:
                    return func(*args)
                else:
                    return {'status' : ret, "msg" : "permission deny"}
        return wrap_func     
    return inner_func
        
@permission_check('getntacl')
def getntacl(path, ck_uid):
    return {'status' : 0, 'data' : _getntacl(path)}

def _setowner(path, uid, recursive):
    sid = uid_to_sid(uid)
    sd = _getntacl(path)
    sddic =  ntacl_parser_from_sd(sd)
    sddic['owner'] = sid
    sddl = sddic2sddl(sddic)
    sd = security.descriptor.from_sddl(sddl, security.dom_sid())
    smbd_set_ntacl(path, sd)
    if recursive == 'on':
        for f in os.listdir(path):
            subpath = path + "/" + f
            if os.path.isfile(subpath):
                _setowner(subpath, uid, 'off')
            else:
                _setowner(subpath, uid, recursive)
    return 0

@permission_check('setowner')
def setowner(path, ck_uid, uid, recursive = 'off'):
    return _setowner(path, uid, recursive)

import re

SEC_DESC_DACL_PRESENT = 0x0004
SEC_DESC_SACL_PRESENT = 0x0010
SEC_DESC_DACL_AUTO_INHERITED = 0x0400
SEC_DESC_SACL_AUTO_INHERITED = 0x0800
SEC_DESC_DACL_PROTECTED = 0x1000

SEC_ACE_FLAG_OBJECT_INHERIT = 0x01       
SEC_ACE_FLAG_CONTAINER_INHERIT = 0x02
SEC_ACE_FLAG_NO_PROPAGATE_INHERIT = 0x04
SEC_ACE_FLAG_INHERIT_ONLY = 0x08  #No set this folder
SEC_ACE_FLAG_INHERITED_ACE = 0x10
SEC_ACE_FLAG_CONTAINER_OBJECT_INHERIT = 0x0b

def ntacl_parser_from_str(sddl):
    # owner, group, dflags, aces
    o_obj = re.search(r'O:(.*?)G', sddl)
    g_obj = re.search(r'G:(.*?)D', sddl)
    d_obj = re.search(r'D:([A-Z]*&?)', sddl)
    aces = re.findall(r'(\(.*?\))', sddl)
    ret = {
        'owner': o_obj.group(1),
        'group': g_obj.group(1),
        'dflags': d_obj.group(1),
        'aces': aces
    }
    return ret

def ntacl_parser_from_sd(sd):
    ret = {}
    ret['owner'] = str(sd.owner_sid)
    ret['group'] = str(sd.group_sid)
    ret['dflags'] = sd.type
    ret['aces'] = {'self' : [], 'inherit' : []} 
    for i in xrange(len(sd.dacl.aces)):
        tace = sd.dacl.aces[i]
        tmp = {
            'type' : tace.type,
            'flags' : tace.flags,
            'access_mask' : tace.access_mask,
            'rid' : str(tace.trustee),
        }
        if tace.flags & SEC_ACE_FLAG_INHERITED_ACE != 0:
            ret['aces']['inherit'].append(dict(tmp))
        else:
            ret['aces']['self'].append(dict(tmp))
    return ret

def num2dflags(flags):
    ret = []
    flag_map = [ 
        (SEC_DESC_DACL_PROTECTED, 'P'), 
        (SEC_DESC_DACL_AUTO_INHERITED, 'AI'), 
    ]
    for m in flag_map:
        if flags & m[0] != 0:
            ret.append(m[1])
    return "".join(ret)

def num2aceflag(flags):
    ret = []
    flag_map = [ 
        (SEC_ACE_FLAG_OBJECT_INHERIT, 'OI'), 
        (SEC_ACE_FLAG_CONTAINER_INHERIT, 'CI'), 
        (SEC_ACE_FLAG_INHERIT_ONLY, 'IO'),
        (SEC_ACE_FLAG_INHERITED_ACE, 'ID'), 
        (SEC_ACE_FLAG_NO_PROPAGATE_INHERIT, 'NP'), 
    ]
    for m in flag_map:
        if flags & m[0] != 0:
            ret.append(m[1])
    return "".join(ret)

def sddic2sddl(sd_dic): 
    sddl = ["O:%sG:%sD:%s"%(sd_dic['owner'], sd_dic['group'], num2dflags(sd_dic['dflags']))]
    daces = []
    aaces = []
    for a in [sd_dic['aces']['self'], sd_dic['aces']['inherit']]:
        for j in xrange(len(a)):
            tmp = [""] * 6
            tmp[0] = 'A' if a[j]['type'] == 0 else 'D'
            tmp[1] = num2aceflag(a[j]['flags'])
            tmp[2] = "0x%08x"%(a[j]['access_mask'])
            tmp[-1] = SmbDefine.map_user(a[j]['rid'])
            if tmp[0] == 'A':
                aaces.append("(%s)"%(";".join(tmp)))
            else:
                daces.append("(%s)"%(";".join(tmp)))
                
    sddl.extend(daces)
    sddl.extend(aaces)
    return "".join(sddl)
    
def get_update_aces(sd_dic, nsd_dic):
    sd_dic['aces']['inherit'] = nsd_dic['aces']['self'] + nsd_dic['aces']['inherit']
    return sddic2sddl(sd_dic)

def get_sd_closure(sd, isFile = True):
    def wrap_func():
        tsd = security.descriptor.from_sddl(sd.as_sddl(), security.dom_sid())
        for i in xrange(len(tsd.dacl.aces) - 1, -1, -1):
            tsd.dacl.aces[i].flags |= SEC_ACE_FLAG_INHERITED_ACE
            if isFile and tsd.dacl.aces[i].flags & SEC_ACE_FLAG_OBJECT_INHERIT == 0:
                tsd.dacl.aces.pop(i)
                continue
        tsd.dacl.num_aces = len(tsd.dacl.aces)
        return tsd
    return wrap_func 

def get_sd_file(sd_dic):
    tdic = copy.deepcopy(sd_dic)
    for i in xrange(len(tdic['aces']['self']) - 1, -1, -1):
        if tdic['aces']['self'][i]['flags'] & SEC_ACE_FLAG_OBJECT_INHERIT == 0:
            tdic['aces']['self'].pop(i)
            continue
        tdic['aces']['self'][i]['flags'] = SEC_ACE_FLAG_INHERITED_ACE

    for i in xrange(len(tdic['aces']['inherit']) - 1, -1, -1):
        if tdic['aces']['inherit'][i]['flags'] & SEC_ACE_FLAG_OBJECT_INHERIT == 0:
            tdic['aces']['inherit'].pop(i)
            continue
        tdic['aces']['inherit'][i]['flags'] = SEC_ACE_FLAG_INHERITED_ACE
    return tdic 

def get_sd_dir(sd_dic):
    tdic = copy.deepcopy(sd_dic)
    for i in xrange(len(tdic['aces']['self']) - 1, -1, -1):
        if tdic['aces']['self'][i]['flags'] == 0: # acl entry is "this folder only"
            tdic['aces']['self'].pop(i)
            continue

        if tdic['aces']['self'][i]['flags'] & SEC_ACE_FLAG_NO_PROPAGATE_INHERIT != 0:
            if tdic['aces']['self'][i]['flags'] & SEC_ACE_FLAG_CONTAINER_INHERIT != 0:
                tdic['aces']['self'][i]['flags'] = 0             
            else:
                tdic['aces']['self'].pop(i)
                continue
        else:
            if tdic['aces']['self'][i]['flags'] & ~(SEC_ACE_FLAG_OBJECT_INHERIT) == 0: # this folder and files
                tdic['aces']['self'][i]['flags'] |= SEC_ACE_FLAG_INHERIT_ONLY # cancel this folder
            
            if tdic['aces']['self'][i]['flags'] & SEC_ACE_FLAG_CONTAINER_INHERIT != 0: # inherit subfolder
                tdic['aces']['self'][i]['flags'] &= ~(SEC_ACE_FLAG_INHERIT_ONLY) # add this folder
            
        tdic['aces']['self'][i]['flags'] |= SEC_ACE_FLAG_INHERITED_ACE

    for i in xrange(len(tdic['aces']['inherit']) - 1, -1, -1):
        if tdic['aces']['inherit'][i]['flags'] == 0:
            tdic['aces']['inherit'].pop(i)
            continue
        tdic['aces']['inherit'][i]['flags'] |= SEC_ACE_FLAG_INHERITED_ACE
    return tdic 


def is_int(uid):
    try:
        int(uid)
        return True
    except:
        return False

def mapacl_owner(owner_sid):
    uid, ut = sid_to_uid(str(owner_sid))
    print uid, ut
    if ut == 3:
        return 0
    else:
        return int(uid)

def set_iftacl(path, sd):
    num_aces = struct.pack(">III", mapacl_owner(sd.owner_sid), mapacl_owner(sd.group_sid), sd.dacl.num_aces)
    aces = []
    for i in xrange(sd.dacl.num_aces):
        ace = sd.dacl.aces[i]
        at = ace.type
        af = ace.flags
        am = ace.access_mask
        uidInfo = sid_to_uid(str(ace.trustee))  
        print uidInfo
         
        if uidInfo[1] == 1: 
            aces.append(struct.pack(">BBIBI",at, af, am, 1, int(uidInfo[0])))
        elif uidInfo[1] == 2:
            aces.append(struct.pack(">BBIBI",at, af, am, 2, int(uidInfo[0])))
        else:
            # special user
            if uidInfo[0] == 'WD':
                aces.append(struct.pack(">BBIBI",at, af, am, 3, 0))
            elif uidInfo[0] == 'CO':
                aces.append(struct.pack(">BBIBI",at, af, am, 4, 0))
            elif uidInfo[0] == 'CG':
                aces.append(struct.pack(">BBIBI",at, af, am, 5, 0))
            else:
                aces.append(struct.pack(">BBIBI",at, af, am, 100, 0)) #others
    print aces
    #xattr.setxattr(path, "security.iftacl", bytearray('1'))
    iftsmb.ift_setxattr(path, "security.iftacl", num_aces + "".join(aces), 4 * 3 + 11 * len(aces))

def smbd_set_mapacl(func):
    def wrap_func(path, sd):
        ret = func(path, sd)
        if ret != 0:
            return {'status' : ret}
        #fullsd = _getntacl(path)
        set_iftacl(path, sd)
        
    return wrap_func

@smbd_set_mapacl
def smbd_set_ntacl(path, sd):
    try:
        smbd.set_nt_acl(path, security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_SACL, sd, service = None)
        return 0
    except:
        return -1

def setntacl_file(fpath, fsd_dic):
    sd = _getntacl(fpath)   
    if sd.type & SEC_DESC_DACL_AUTO_INHERITED == 0 and sd.type & SEC_DESC_SACL_PRESENT != 0:
        #print "Not set acl", fpath
        return

    if sd.type & SEC_DESC_DACL_PROTECTED != 0:
        #print "Not set acl", fpath
        return

    sd_dic = ntacl_parser_from_sd(sd)
    rsddl = get_update_aces(sd_dic, fsd_dic)
    smbd_set_ntacl(fpath, security.descriptor.from_sddl(rsddl, security.dom_sid()))

def setntacl_dir(dpath, dsd_dic):
    sd = _getntacl(dpath)   
    if sd.type & SEC_DESC_DACL_AUTO_INHERITED == 0 and sd.type & SEC_DESC_SACL_PRESENT != 0:
        #print "Not set acl", dpath
        return

    if sd.type & SEC_DESC_DACL_PROTECTED != 0:
        #print "Not set acl", dpath
        return

    sd_dic = ntacl_parser_from_sd(sd)
    rsddl = get_update_aces(sd_dic, dsd_dic)
    smbd_set_ntacl(dpath, security.descriptor.from_sddl(rsddl, security.dom_sid()))

    fsd_dic = get_sd_file(sd_dic)
    dsd_dic = get_sd_dir(sd_dic)
    for f in os.listdir(dpath):
        subpath = dpath + "/" + f
        if os.path.isfile(subpath):
            setntacl_file(subpath, fsd_dic)
        else:
            setntacl_dir(subpath, dsd_dic)

@permission_check('setntacl')
def setntacl(rootpath, ck_uid, sddl):
    s3conf = s3param.get_context()
    s3conf.load("/etc/samba/smb.conf")
    sd = security.descriptor.from_sddl(sddl, security.dom_sid())
    smbd_set_ntacl(rootpath, sd)

    if os.path.isfile(rootpath):
        return {'status' : 0}

    sd_dic = ntacl_parser_from_sd(sd)
    fsd_dic = get_sd_file(sd_dic)
    dsd_dic = get_sd_dir(sd_dic)
    for f in os.listdir(rootpath):
        subpath = rootpath + "/" + f
        if os.path.isfile(subpath):
            setntacl_file(subpath, fsd_dic)
        else:
            setntacl_dir(subpath, dsd_dic)
    return {'status' : 0}

def replacentacl_file(fpath, fsd_dic):
    rsddl = sddic2sddl(fsd_dic)
    smbd_set_ntacl(fpath, security.descriptor.from_sddl(rsddl, security.dom_sid()))

def replacentacl_dir(dpath, dsd_dic):
    rsddl = sddic2sddl(dsd_dic)
    smbd_set_ntacl(dpath, security.descriptor.from_sddl(rsddl, security.dom_sid()))

    fsd_dic = get_sd_file(dsd_dic)
    dsd_dic = get_sd_dir(dsd_dic)
    for f in os.listdir(dpath):
        subpath = dpath + "/" + f
        if os.path.isfile(subpath):
            replacentacl_file(subpath, fsd_dic)
        else:
            replacentacl_dir(subpath, dsd_dic)

@permission_check('setntacl')
def replacentacl(rootpath, ck_uid, sddl):
    s3conf = s3param.get_context()
    s3conf.load("/etc/samba/smb.conf")
    sd = security.descriptor.from_sddl(sddl, security.dom_sid())
    smbd_set_ntacl(rootpath, sd)

    if os.path.isfile(rootpath):
        return {'status' : 0}

    sd_dic = ntacl_parser_from_sd(sd)
    fsd_dic = get_sd_file(sd_dic)
    dsd_dic = get_sd_dir(sd_dic)
    for f in os.listdir(rootpath):
        subpath = rootpath + "/" + f
        if os.path.isfile(subpath):
            replacentacl_file(subpath, fsd_dic)
        else:
            replacentacl_dir(subpath, dsd_dic)
    return {'status' : 0}

def permission_check_api(uid, path, mask):
    sids = get_sids_from_uid(uid)
    sd = _getntacl(path)
    return ntacl_permission_check.permission_check(sids, sd, int(mask))

def test_setntacl(rootpath, sddl):
    s3conf = s3param.get_context()
    s3conf.load("/etc/samba/smb.conf")
    sd = security.descriptor.from_sddl(sddl, security.dom_sid())
    smbd_set_ntacl(rootpath, sd)

def test_sd(sddl):
    s3conf = s3param.get_context()
    s3conf.load("/etc/samba/smb.conf")
    sd = security.descriptor.from_sddl(sddl, security.dom_sid())
    return sd
    
def test_getntacl(path):
    sd = _getntacl(path)
    print sd.as_sddl()

def test_uid_to_sid(uid):
    print uid_to_sid(int(uid))

def test_gid_to_sid(gid):
    print gid_to_sid(int(gid))

def test_uid_to_sid_winbind(uid):
    for i in xrange(100):
        print uid_to_sid_winbind(int(uid))

def test_gid_to_sid_winbind(gid):
    print gid_to_sid_winbind(int(gid))

def test_sid_to_uid(sid):
    print sid_to_uid(sid)

def main():
    func = getattr(sys.modules[__name__], sys.argv[1])
    func(*sys.argv[2:])
    
if __name__ == "__main__":
    main()
