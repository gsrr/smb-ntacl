import sys
import pwd
import ctypes
import struct

global_libc = ctypes.CDLL("libc.so.6")
global_libwb = ctypes.CDLL("libwbclient.so")

WBC_MAXSUBAUTHS = 15
WBC_SID_STRING_BUFLEN = 15*11+25

ARRID = ctypes.c_ubyte * 6
ARRSUB = ctypes.c_uint * WBC_MAXSUBAUTHS

class wbcDomainSid(ctypes.Structure):
    _fields_ = [
        ("sid_rev_num", ctypes.c_ubyte),
        ("num_auths", ctypes.c_ubyte),
        ("id_auth", ARRID),
        ("sub_auths", ARRSUB),
    ]

def wb_uid_to_sid(uid):
    sid_str = (ctypes.c_byte * WBC_SID_STRING_BUFLEN)()
    uid = ctypes.c_int(uid)
    sid = wbcDomainSid()
    psid = ctypes.pointer(sid)
    status = global_libwb.wbcUidToSid(uid, psid)
    if status != 0:
        return "S-0-0"
    global_libwb.wbcSidToStringBuf(psid, sid_str, WBC_SID_STRING_BUFLEN)
    return ctypes.cast(sid_str, ctypes.c_char_p).value

def wb_gid_to_sid(uid):
    sid_str = (ctypes.c_byte * WBC_SID_STRING_BUFLEN)()
    uid = ctypes.c_int(uid)
    sid = wbcDomainSid()
    psid = ctypes.pointer(sid)
    status = global_libwb.wbcGidToSid(uid, psid)
    if status != 0:
        return "S-0-0"
    global_libwb.wbcSidToStringBuf(psid, sid_str, WBC_SID_STRING_BUFLEN)
    return ctypes.cast(sid_str, ctypes.c_char_p).value

def get_uid_groups(uid):
    pw = pwd.getpwuid(uid)
    user = ctypes.c_char_p(pw.pw_name)
    gid = ctypes.c_int(pw.pw_gid)
    num = ctypes.c_int(10)
    arr = (ctypes.c_int * 10)()
    pn = ctypes.pointer(num)
    gs = ctypes.cast(arr, ctypes.POINTER(ctypes.c_int))

    while True:
        ngroup = global_libc.getgrouplist(user, gid, gs, pn)
        if ngroup == -1:
            num = c_int(num.value * 2)
            pn = ctypes.pointer(num)
        elif ngroup >= 0: 
            return (ngroup, gs)

def ift_setxattr(path, name, value, length):
    path = ctypes.c_char_p(path)
    name = ctypes.c_char_p(name)
    varr = (ctypes.c_byte * length)()
    size = ctypes.c_int(length)
    for i in xrange(length):
        varr[i] = ctypes.c_byte(ord(value[i]))
    #sid_str[0] = c_byte(0xA)
    global_libc.setxattr(path, name, varr, size, ctypes.c_int(0))

def main():
    print get_uid_groups(100001)
    print wb_uid_to_sid(100001)
    print wb_uid_to_sid(1002)
    # "000000030100001f01ff01000186a30000001f01ff01000186a10000001f01ff01000186a2"
    value = struct.pack('>IBBIBI', 3, 0, 0, 0x1f01ff, 1, 100001)
    value2 = struct.pack('>BBIBI', 0, 0, 0x1f01ff, 1, 100001)
    ift_setxattr("/tmp", "security.iftacl", value + value2, 26)

if __name__ == "__main__":
    main()
