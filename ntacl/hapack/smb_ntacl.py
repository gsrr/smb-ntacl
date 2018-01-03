# getntacl and setntacl script
import sys
import os
import copy
import commands
from samba.samba3 import param as s3param
from samba.dcerpc import security
from samba.samba3 import smbd, passdb

def get_lp(conf):
    lp = s3param.get_context()
    lp.load(conf)
    return lp

def get_pdb(conf):
    lp = s3param.get_context()
    lp.load(conf)
    pdb = passdb.PDB(lp.get('passdb backend'))
    return pdb

def is_uid_local(uid):
    try:
        pdb = get_pdb("/etc/samba/smb.conf.default")
        lp.set("passdb backend", 'tdbsam')
        sid = pdb.uid_to_sid(int(uid))    
        return str(sid)
    except:
        return None

def uid_to_sid_winbind(uid):
    sid = commands.getoutput("wbinfo -U %d"%uid).strip()
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
    
def uid_to_sid(uid):
    sid = is_uid_local(uid) 
    if sid != None:
        return sid

    sid = is_uid_domain(uid) 
    if sid != None:
        return sid

    return "S-1-22-1-%d"%uid

def is_gid_local(gid):
    try:
        pdb = get_pdb("/etc/samba/smb.conf")
        lp.set("passdb backend", 'tdbsam')
        sid = pdb.gid_to_sid(int(gid))    
        return str(sid)
    except:
        return None

def gid_to_sid_winbind(gid):
    sid = commands.getoutput("wbinfo -G %d"%gid).strip()
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

def gid_to_sid(gid):
    sid = is_gid_local(gid) 
    if sid != None:
        return sid

    sid = is_gid_domain(gid) 
    if sid != None:
        return sid

    return "S-1-22-2-%d"%gid

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
    def map_uid2sid(uid):
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
          
def map_uid2sid(uid):	
    return SmbDefine.map_uid2sid(uid)

def is_sid_local(sid):
    try:
        pdb = get_pdb("/etc/samba/smb.conf.default")
        lp.set("passdb backend", 'tdbsam')
        uinfo = pdb.sid_to_uid(int(uid))    
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
        uinfo = pdb.sid_to_uid(int(uid))    
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
        if "S-1-22-1" in sid:
            return (sid, 1)
        elif "S-1-22-2" in sid:
            return (sid, 2)
        else:
            return (sid, 1)
    
def sid_to_uid(sid):
    uinfo = is_sid_local(sid)
    if uinfo != None:
        return uinfo
    
    uinfo = is_sid_domain(sid) 
    return uinfo

def getntacl_util(path):
    s3conf = s3param.get_context()
    s3conf.load("/etc/samba/smb.conf")
    sd = smbd.get_nt_acl(path, security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_SACL, service=None)
    return sd

def getntacl(path, sddl = None):
    return getntacl_util(path)

def setowner(path, sid):
    sd = getntacl(path)
    sddic =  ntacl_parser_from_sd(sd)
    sddic['owner'] = sid
    sddl = sddic2sddl(sddic)
    print sddl
    sd = security.descriptor.from_sddl(sddl, security.dom_sid())
    smbd_set_ntacl(path, sd)
    return 0

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

def smbd_set_ntacl(path, sd):
    smbd.set_nt_acl(path, security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_SACL, sd, service = None)

def setntacl_file(fpath, fsd_dic):
    print fpath
    sd = getntacl_util(fpath)   
    if sd.type & SEC_DESC_DACL_AUTO_INHERITED == 0 and sd.type & SEC_DESC_SACL_PRESENT != 0:
        print "Not set acl", fpath
        return

    if sd.type & SEC_DESC_DACL_PROTECTED != 0:
        print "Not set acl", fpath
        return

    sd_dic = ntacl_parser_from_sd(sd)
    rsddl = get_update_aces(sd_dic, fsd_dic)
    smbd_set_ntacl(fpath, security.descriptor.from_sddl(rsddl, security.dom_sid()))

def setntacl_dir(dpath, dsd_dic):
    print dpath
    sd = getntacl_util(dpath)   
    if sd.type & SEC_DESC_DACL_AUTO_INHERITED == 0 and sd.type & SEC_DESC_SACL_PRESENT != 0:
        print "Not set acl", dpath
        return

    if sd.type & SEC_DESC_DACL_PROTECTED != 0:
        print "Not set acl", dpath
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

def setntacl(rootpath, sddl):
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

def replacentacl(rootpath, sddl):
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
    sd = getntacl(path)
    print sd.as_sddl()

def test_map_uid2sid():
    print map_uid2sid("u11001206")

def main():
    if sys.argv[1] == "getntacl":
        print getntacl(sys.argv[2])
    elif sys.argv[1] == "test_setntacl":
        test_setntacl(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "ntacl_parser":
        ntacl_parser(sys.argv[2])
    else:
        func = getattr(sys.modules[__name__], sys.argv[1])
        func()
    
if __name__ == "__main__":
    main()