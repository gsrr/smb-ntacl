import traceback
import sys
import os
import subprocess
import smb_ntacl
import copy
import commands
import json

SEC_ACE_FLAG_INHERITED_ACE = 0x0010

def sd_get_aces(dacl):
    data = []
    for i in xrange(dacl.num_aces):
        tmp = {}
        ace = dacl.aces[i]
        tmp['at'] = ace.type
        tmp['af'] = int(ace.flags)
        tmp['am'] = int(ace.access_mask)
        uid,stype = smb_ntacl.sid_to_uid(str(ace.trustee))
        if stype == 1:
            tmp['u'] = uid
        else:
            tmp['g'] = uid
        data.append(tmp)
    return data

def sd2dict(path, sd):
    data = {'path' : path, 'acl' : {}}
    data['acl']['O'] = smb_ntacl.sid_to_uid(str(sd.owner_sid))[0]
    data['acl']['G'] = smb_ntacl.sid_to_uid(str(sd.group_sid))[0]
    data['acl']['aces'] = sd_get_aces(sd.dacl)
    return data

def sd_replace_acl(sddic, acl):
    line = commands.getoutput("net getlocalsid")
    sddic['aces'] = {'self' : [], 'inherit' : []}
    acls = acl.split(":")
    for astr in acls:
        a = astr.strip("(").strip(")").split(";") 
        tmp = {}
        tmp['type'] = int(a[0])
        tmp['flags'] = int(a[1])
        tmp['access_mask'] = int(a[2])
        if a[3][0] == 'u':
            tmp['rid'] = smb_ntacl.uid_to_sid(int(a[3][1:]))
        else: #g
            tmp['rid'] = smb_ntacl.gid_to_sid(int(a[3][1:]))
            
        if tmp['flags'] & SEC_ACE_FLAG_INHERITED_ACE != 0:
            sddic['aces']['inherit'].append(tmp)
        else:
            sddic['aces']['self'].append(tmp)

def acl2sddl(path, acl):
    sd = smb_ntacl._getntacl(path)
    sddic = smb_ntacl.ntacl_parser_from_sd(sd)
    sd_replace_acl(sddic, acl)
    return smb_ntacl.sddic2sddl(sddic)

def ntacl_lib_get(HAServer, paraList):
    if os.path.exists(paraList['path']) == False:
        return {'status' : 0}
    ret = smb_ntacl.getntacl(paraList['path'], int(paraList['ck_uid']))
    if ret['status'] != 0:
        return ret
    data = sd2dict(paraList['path'], ret['data'])
    return {'status' : 0 , 'data' : data}

def ntacl_lib_set(HAServer, paraList):
    if os.path.exists(paraList['path']) == False:
        return {'status' : 0}

    if paraList.has_key('acl'):
        sddl = acl2sddl(paraList['path'], paraList['acl'])
        sd = smb_ntacl.setntacl(paraList['path'], int(paraList['ck_uid']), sddl)
    return {'status' : 0}

def ntacl_lib_setown(HAServer, paraList):
    try:
        if os.path.exists(paraList['path']) == False:
            return {'status' : 0}
        
        ret = smb_ntacl.setowner(*[paraList['path'], int(paraList['ck_uid']), int(paraList['uid'])])
        return ret
    except:
        print traceback.format_exc()

def ntacl_lib_replace(HAServer, paraList):
    try:
        if os.path.exists(paraList['path']) == False:
            return {'status' : 0}

        if paraList.has_key('acl'):
            sddl = acl2sddl(paraList['path'], paraList['acl'])
            ret = smb_ntacl.replacentacl(paraList['path'], int(paraList['ck_uid']), sddl)
        return ret
    except:
        print traceback.format_exc()

def ntacllib(HAServer, paraList):
        try:
                reload(smb_ntacl)
                op = paraList['op']
                func = getattr(sys.modules[__name__], op)
                return func(HAServer, paraList)
        except:
                return {'status' : -999, 'exception' : traceback.format_exc()}


def test_ntacl_lib_get(HA):
    paras = {
        'path' : sys.argv[2],
        'controller' : 'A',
        'serviceId' : '0',
    }
    print ntacl_lib_get(HA, paras)

def test_ntacl_lib_set(HA):
    paras = {
        'path' : sys.argv[2],
        'acl' : "(0;0;2032031;100001):(0;0;1179785;WD)",
        'controller' : 'A',
        'serviceId' : '0',
    }
    print ntacl_lib_set(HA, paras)

def test_ntacl_lib_set_prop1(HA):
    paras = {
        'path' : sys.argv[2],
        'acl' : "(0;17;2032031;100001):(0;17;1179785;WD)",
        'controller' : 'A',
        'serviceId' : '0',
    }
    print ntacl_lib_set(HA, paras)

def test_ntacl_lib_setown(HA):
    paras = {
        'path' : sys.argv[2],
        'uid' : '1000',
        'controller' : 'A',
        'serviceId' : '0',
    }
    print ntacl_lib_setown(HA, paras)

def test_ntacl_lib_replace(HA):
    paras = {
        'path' : sys.argv[2],
        'acl' : "(0;0;2032031;100001):(0;0;1179785;WD)",
        'controller' : 'A',
        'serviceId' : '0',
    }
    print ntacl_lib_replace(HA, paras)

if __name__ == "__main__":
        try:
                sys.path.append("/usr/local/NAS/misc/HAAgent")
                from NASHAComm import *
                HA = NASHAComm("127.0.0.1")
                func = getattr(sys.modules[__name__], sys.argv[1])      
                func(HA)
        except:
                pass
        finally:
                HA.closeSocket()
                
