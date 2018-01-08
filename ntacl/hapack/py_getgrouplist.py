import sys
import pwd
import ctypes

def get_uid_groups(uid):
    libc = ctypes.CDLL("libc.so.6")
    pw = pwd.getpwuid(uid)
    user = ctypes.c_char_p(pw.pw_name)
    gid = ctypes.c_int(pw.pw_gid)
    num = ctypes.c_int(10)
    arr = (ctypes.c_int * 10)()
    pn = ctypes.pointer(num)
    gs = ctypes.cast(arr, ctypes.POINTER(ctypes.c_int))

    while True:
        ngroup = libc.getgrouplist(user, gid, gs, pn)
        if ngroup == -1:
            num = c_int(num.value * 2)
            pn = ctypes.pointer(num)
        elif ngroup >= 0: 
            return (ngroup, gs)


def main():
    print get_uid_groups(100001)

if __name__ == "__main__":
    main()
