import sys
import traceback

def restorentacl(HAServer, paraList = None):
    return {'status' : 0}

def main(HAServer):
    func = getattr(sys.modules[__name__], sys.argv[1])
    func(HAServer)
    
if __name__ == "__main__":
    try:
        sys.path.append("/usr/local/NAS/misc/HAAgent")
        from NASHAComm import *
        HA = NASHAComm("127.0.0.1")
        main(HA)
    except:
        print traceback.format_exc()
    finally:
        HA.closeSocket()


