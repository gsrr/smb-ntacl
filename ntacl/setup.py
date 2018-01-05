import traceback
import sys
import os
from distutils.core import setup

def walkall(rootdir, deployMnt):
    data = []
    for (dirpath, dirnames, filenames) in os.walk(rootdir):
        if len(filenames) != 0:
            data.append(("/" + dirpath.split("/", 1)[1], [dirpath + "/" + f for f in filenames]))
            data.append((deployMnt + "/NAS/misc/SystemFiles/" + dirpath.split("/", 1)[1], [dirpath + "/" + f for f in filenames]))
    return data

def callSetup(deployMnt):
    sys.argv.pop(1)
    setup(
        name="ntacl",
        version='0.1',
        packages=[],
        license='Creative Commons Attribution-Noncommercial-Share Alike license',
        long_description=open('README').read(),
        data_files=[
            (deployMnt + '/NAS/misc/Cmd/Exec/System', ['hapack/ntacl.py']),
            (deployMnt + '/NAS/misc/Cmd/CmdTool/Parser', ['hapack/ntaclparser.py']),
            (deployMnt + '/NAS/misc/HAAgent/Lib/System', ['hapack/ntacllib.py']),
            (deployMnt + '/NAS/misc/HAAgent/Config', ['hapack/NTACLConfig.py']),
            (deployMnt + '/NAS/misc/agent/python/ntacl', ['hapack/ntaclcmd.py']),
            ('/usr/lib64/python2.7/site-packages', ['hapack/smb_ntacl.py']),
            (deployMnt + '/NAS/misc/HAAgent/Lib/User', ['hapack/restoreUser.py']),
            (deployMnt + '/NAS/misc/HAAgent/Lib/User', ['hapack/userOperation.py']),
        ] + walkall("buildroot", deployMnt),
     )

def removefile(path):
    try:
        os.remove(path)
        print "remove ", path
    except:
        print traceback.format_exc()
        pass
    
# python setup.py install --record files.txt
# cat files.txt | xargs rm -rf
# use pip instead?
def uninstall():
    with open("files.txt", "r") as fr:
        lines = fr.readlines()
        for line in lines:
            line = line.strip()
            removefile(line)

def main():
    try:
        func = getattr(sys.modules[__name__], sys.argv[1])
        func()
    except:
        print "call setup : deploying..."
        #print traceback.format_exc()
        callSetup(sys.argv[1])

if __name__ == "__main__":
    main()
