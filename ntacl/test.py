import os
import sys
import nascmd_client
import smb_ntacl

FOLDER_SUB_FILE = 17
FILE = 4097

# smbd.chown("/tmp/folder", 1000, 1000)

'''
*1. Deny --> ok
*2. replace all child --> remove self-permission for every child
3. inherit from
*4. take owner
*5. local and domain user/group (ad, ldap, nis) --> (lu, lg), (au), (ldu, ldg), (uu, ug)
6. map unix group to smb group
'''

def testcmd_modifygroup():
    os.system('echo -e "useradmin group add group002 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "useradmin group delete group102 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "useradmin group modify group002 -n group102 -z a@0\nexit\n" | NASCLI')
    os.system("net groupmap list")

def testcmd_deletegroup():
    os.system('echo -e "useradmin group delete group002 -z a@0\nexit\n" | NASCLI')
    os.system("net groupmap list")

def testcmd_addgroup_new():
    os.system('echo -e "useradmin group delete group002 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "useradmin group add group002 -z a@0\nexit\n" | NASCLI')
    os.system("net groupmap list")

def testcmd_set_folder_replaceAll1(): # this folder, subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('python hapack/ntaclcmd.py replace -f /tmp/folder -a (0;3;2032127;u1022):(0;3;1179785;WD)')
    os.system('python hapack/ntaclcmd.py get -f /tmp/folder')
    os.system('python hapack/ntaclcmd.py get -f /tmp/folder/file1')
    os.system('python hapack/ntaclcmd.py get -f /tmp/folder/file2')

def test_set_folder_propagate1(): # this folder, subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('python hapack/ntaclcmd set -f /tmp/folder -a (0;3;2032127;u1022):(0;3;1179785;WD)')
    os.system('python hapack/ntaclcmd.py get -f /tmp/folder')
    os.system('python hapack/ntaclcmd.py get -f /tmp/folder/file1')
    os.system('python hapack/ntaclcmd.py get -f /tmp/folder/file2')

def testcmd_set_file():
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("touch /tmp/folder/file")
    os.system('python hapack/ntaclcmd.py -f /tmp/folder/file -a (0;0;2032031;u100001):(0;0;1179785;WD)')
    os.system('python hapack/ntaclcmd.py get -f /tmp/folder/file')

def testcmd_take_owner(): # take owner
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('python hapack/ntaclcmd.py setown -o u1133 -f /tmp/folder')
    os.system('python hapack/ntaclcmd.py get -f /tmp/folder')

def test_set_ldapuser(): # this folder, subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;3;2032127;u1000001):(0;3;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_adgroup(): # this folder, subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;3;2032127;g11000553):(0;3;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_aduser(): # this folder, subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;3;2032127;u11001702):(0;3;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_replaceAll1(): # this folder, subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl replace -f /tmp/folder -a (0;3;2032127;u1022):(0;3;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_take_owner(): # take owner
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl setown -f /tmp/folder -o u1033 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')

def test_set_folder_deny(): # this folder, subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;3;2032127;1022):(1;3;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_nopropagate2(): # subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;7;2032127;1022):(0;15;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_nopropagate2(): # subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;7;2032127;1022):(0;15;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_nopropagate1(): # this folder, subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;7;2032127;1022):(0;7;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_propagate7(): # files
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file3")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;3;2032127;1022):(0;9;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_propagate6(): # subfolder
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file3")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;3;2032127;1022):(0;10;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_propagate5(): # subfolder and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file3")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;3;2032127;1022):(0;11;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_propagate4(): # this folder, file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;1;2032127;1022):(0;1;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_propagate3(): # this folder, subfolder
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;2;2032127;1022):(0;2;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_propagate2(): # this folder
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;0;2032127;1022):(0;0;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_set_folder_propagate1(): # this folder, subfolder, and file
    os.system("rm -rf /tmp/folder")
    os.system("mkdir /tmp/folder")
    os.system("mkdir /tmp/folder/subfolder1")
    os.system("mkdir /tmp/folder/subfolder1/subfolder2")
    os.system("touch /tmp/folder/file1")
    os.system("touch /tmp/folder/file2")
    os.system("touch /tmp/folder/subfolder1/file3")
    os.system("touch /tmp/folder/subfolder1/subfolder2/file4")
    os.system('echo -e "ntacl set -f /tmp/folder -a (0;3;2032127;u1022):(0;3;1179785;WD) -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file1 -z a@0\nexit\n" | NASCLI')
    os.system('echo -e "ntacl get -f /tmp/folder/file2 -z a@0\nexit\n" | NASCLI')

def test_integrate(func):
    def wrap_func(tpath):
        s_sddl = "O:S-1-5-21-2896997548-2896997548-2896997548-100001G:S-1-22-2-0D:(A;;0x001f01ff;;;S-1-5-21-2896997548-2896997548-2896997548-100001)"
        func(tpath)
        sd = smb_ntacl._getntacl(tpath)    
        print sd.as_sddl()
        print s_sddl
        print sd.as_sddl() == s_sddl
    return wrap_func

def execcmds(cmds):
    for cmd in cmds:
        os.system(cmd)

@test_integrate
def test_replace_file(tpath):
    cmds = [
        'rm -rf /tmp/folder',
        'mkdir /tmp/folder',
        'touch /tmp/folder/file',
        'echo -e "ntacl replace -f /tmp/folder -a (0;3;2032127;u100001) -z a@0\nexit\n" | NASCLI',
        'echo -e "ntacl setown -f /tmp/folder/file -o u100001 -z a@0\nexit\n" | NASCLI',
        'echo -e "ntacl get -f /tmp/folder/file -z a@0\nexit\n" | NASCLI',
    ]
    execcmds(cmds)

@test_integrate
def test_set_file(tpath):
    cmds = [
        'rm -rf /tmp/folder',
        'mkdir /tmp/folder',
        'touch /tmp/folder/file',
        'echo -e "ntacl set -f /tmp/folder/file -a (0;0;2032127;u100001) -z a@0\nexit\n" | NASCLI',
        'echo -e "ntacl setown -f /tmp/folder/file -o u100001 -z a@0\nexit\n" | NASCLI',
        'echo -e "ntacl get -f /tmp/folder/file -z a@0\nexit\n" | NASCLI',
    ]
    execcmds(cmds)

def test_get_file():
    cmds = [
        'rm -rf /tmp/folder',
        'mkdir /tmp/folder',
        'touch /tmp/folder/file',
        'echo -e "ntacl get -f /tmp/folder/file -z a@0\nexit\n" | NASCLI',
    ]
    execcmds(cmds)

def main():
    func = getattr(sys.modules[__name__], sys.argv[1])
    func(*sys.argv[2:])

if __name__ == "__main__":
    main()
