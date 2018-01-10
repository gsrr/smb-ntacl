import sys
import pwd
import ctypes

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

def main():
    print get_uid_groups(100001)
    print wb_uid_to_sid(100001)
    print wb_uid_to_sid(1002)

if __name__ == "__main__":
    main()
