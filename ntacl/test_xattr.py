from ctypes import *

lib = cdll.LoadLibrary("libc.so.6")

path = c_char_p("/tmp")
name = c_char_p("security.iftacl")
sid_str = (c_byte * 5)(0,0xA,0,0,0)
sid_str[0] = c_byte(0xA)
size = c_int(5)
lib.setxattr(path, name, sid_str, size, c_int(0))

