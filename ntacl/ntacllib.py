# getntacl and setntacl script
import sys
import os
import copy
from samba.samba3 import param as s3param
from samba.dcerpc import security
from samba.samba3 import smbd


def getntacl_util(path):
    s3conf = s3param.get_context()
    s3conf.load("/etc/samba/smb.conf")
    sd = smbd.get_nt_acl(path, security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_SACL, service=None)
    return sd

def getntacl(path, sddl = None):
    raw_input()
    sd = getntacl_util(path)
    print "sd type:%x"%sd.type
    for i in xrange(len(sd.dacl.aces)):
        print "type:", "%x"%sd.dacl.aces[i].type
        print "flags:", "%x"%sd.dacl.aces[i].flags
        print "access_mask:", "%x"%sd.dacl.aces[i].access_mask
        print "uid:", sd.dacl.aces[i].trustee.sub_auths
    print sd.__ndr_print__()
    return sd.as_sddl()

def setntacl_chown(path):
    sd = security.descriptor.from_sddl(sddl, security.dom_sid())
    print sd.owner_sid

import re

SEC_DESC_DACL_PRESENT = 0x0004
SEC_DESC_SACL_PRESENT = 0x0010
SEC_DESC_DACL_AUTO_INHERITED = 0x0400
SEC_DESC_SACL_AUTO_INHERITED = 0x0800
SEC_DESC_DACL_PROTECTED = 0x1000

SEC_ACE_FLAG_OBJECT_INHERIT = 0x0001       
SEC_ACE_FLAG_CONTAINER_INHERIT = 0x0002
SEC_ACE_FLAG_INHERIT_ONLY = 0x1000
SEC_ACE_FLAG_INHERITED_ACE = 0x0010

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
        if m[0] == SEC_DESC_DACL_AUTO_INHERITED or flags & m[0] != 0:
            ret.append(m[1])
    return "".join(ret)

def num2aceflag(flags):
    ret = []
    flag_map = [ 
        (SEC_ACE_FLAG_OBJECT_INHERIT, 'OI'), 
        (SEC_ACE_FLAG_CONTAINER_INHERIT, 'CI'), 
        (SEC_ACE_FLAG_INHERIT_ONLY, 'IO'),
        (SEC_ACE_FLAG_INHERITED_ACE, 'ID'), 
    ]
    for m in flag_map:
        if flags & m[0] != 0:
            ret.append(m[1])
    return "".join(ret)

def get_update_aces(sd_dic, nsd_dic):
    sd_dic['aces']['inherit'] = nsd_dic['aces']['self'] + nsd_dic['aces']['inherit']
    sddl = ["O:%sG:%sD:%s"%(sd_dic['owner'], sd_dic['group'], num2dflags(sd_dic['dflags']))]
    daces = []
    aaces = []
    for a in [sd_dic['aces']['self'], sd_dic['aces']['inherit']]:
        for j in xrange(len(a)):
            tmp = [""] * 6
            tmp[0] = 'A' if a[j]['type'] == 0 else 'D'
            tmp[1] = num2aceflag(a[j]['flags'])
            tmp[2] = "0x%x"%(a[j]['access_mask'])
            tmp[-1] = a[j]['rid']
            if tmp[0] == 'A':
                aaces.append("(%s)"%(";".join(tmp)))
            else:
                daces.append("(%s)"%(";".join(tmp)))
                
    sddl.extend(daces)
    sddl.extend(aaces)
    return "".join(sddl)

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
        if tdic['aces']['self'][i]['flags'] == 0:
            tdic['aces']['self'].pop(i)
            continue
        tdic['aces']['self'][i]['flags'] |= SEC_ACE_FLAG_INHERITED_ACE

    for i in xrange(len(tdic['aces']['inherit']) - 1, -1, -1):
        if tdic['aces']['self'][i]['flags'] == 0:
            tdic['aces']['self'].pop(i)
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
    print rootpath
    s3conf = s3param.get_context()
    s3conf.load("/etc/samba/smb.conf")
    sd = security.descriptor.from_sddl(sddl, security.dom_sid())
    smbd_set_ntacl(rootpath, sd)

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
    
def main():
    if sys.argv[1] == "getntacl":
        print getntacl(sys.argv[2])
    elif sys.argv[1] == "test_setntacl":
        test_setntacl(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "ntacl_parser":
        ntacl_parser(sys.argv[2])
    else:
        setntacl(sys.argv[2], sys.argv[3])
    
if __name__ == "__main__":
    main()