import cmd
import traceback
import shlex

import sys
sys.path.append("/usr/local/NAS/misc/HAAgent/Lib/System/")
import ntacllib
import argparse
import json



class FakeHA:
    def log(self, level, msg):
        pass
    
    def callGetLocalFunc(self, cmd, paras):
        return ntacllib.ntacllib(self, paras)

class NTACLParser:
    def __init__(self):
        self.cmds = ['ntacl_test', 'ntacl_get', 'ntacl_set', 'ntacl_setown', 'ntacl_replace']
        self.parser_ntacl = argparse.ArgumentParser(prog="ntacl", add_help=False)
        self.parser_ntacl_test = argparse.ArgumentParser(prog="ntacl_test", add_help=False)
        self.parser_ntacl_test.add_argument("-z", nargs="?", required=True)

        self.parser_ntacl_get = argparse.ArgumentParser(prog="ntacl_get", add_help=False)
        self.parser_ntacl_get.add_argument("-f", nargs="?", required=True)
        self.parser_ntacl_get.add_argument("-z", nargs="?", required=True)

        self.parser_ntacl_set = argparse.ArgumentParser(prog="ntacl_set", add_help=False)
        self.parser_ntacl_set.add_argument("-f", nargs="?", required=True)
        self.parser_ntacl_set.add_argument("-a", nargs="?", required=True)
        self.parser_ntacl_set.add_argument("-z", nargs="?", required=True)

        self.parser_ntacl_setown = argparse.ArgumentParser(prog="ntacl_setown", add_help=False)
        self.parser_ntacl_setown.add_argument("-f", nargs="?", required=True)
        self.parser_ntacl_setown.add_argument("-o", nargs="?", required=True)

        self.parser_ntacl_replace = argparse.ArgumentParser(prog="ntacl_replace", add_help=False)
        self.parser_ntacl_replace.add_argument("-f", nargs="?", required=True)
        self.parser_ntacl_replace.add_argument("-a", nargs="?", required=True)
        self.parser_ntacl_replace.add_argument("-z", nargs="?", required=True)

    def find(self, args):
        cnt = 0
        cmd = "ntacl"
        while cnt < len(args):
            cmd += ("_" + args[cnt])
            if cmd in self.cmds:
                break
            cnt += 1
        args = args[cnt+1:]
        namespace = getattr(self, "parser" + "_" + cmd).parse_args(args).__dict__
        return cmd, namespace

class ntacl(cmd.Cmd):

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.name = ntacl
        self.parsers = NTACLParser()
        self.ha = FakeHA()

    def do_ntacl(self, args_list):
        ret = {'status': 0}
        try:
            cmd, namespace = self.parsers.find(args_list)
            func_name = "cmd_" + cmd
            ret = self.adapter_cmd(namespace, func_name)
        except:
            print traceback.format_exc()
            ret = {'status': 2}
        finally:
            return ret

    def adapter_cmd(self, args, func_name):
        ret = getattr(self, func_name)(args)
        return json.dumps(ret, ensure_ascii=False)

    def cmd_ntacl_test(self, args):
        paras = {}
        paras['op'] = "ntacl_lib_test"
        paras['controller'] = args['ctrl']
        paras['serviceId'] = args['wwn']
        ret = self.ha.callGetLocalFunc("ntacllib", paras)
        return ret

    def cmd_ntacl_get(self, args):
        paras = {}
        paras['op'] = "ntacl_lib_get"
        paras['path'] = args['f']
        ret = self.ha.callGetLocalFunc("ntacllib", paras)
        return ret

    def cmd_ntacl_set(self, args):
        paras = {}
        paras['op'] = "ntacl_lib_set"
        paras['acl'] = args['a']
        paras['path'] = args['f']
        ret = self.ha.callGetLocalFunc("ntacllib", paras)
        return ret

    def cmd_ntacl_setown(self, args):
        paras = {}
        paras['op'] = "ntacl_lib_setown"
        paras['uid'] = args['o']
        paras['path'] = args['f']
        ret = self.ha.callGetLocalFunc("ntacllib", paras)
        return ret

    def cmd_ntacl_replace(self, args):
        paras = {}
        paras['op'] = "ntacl_lib_replace"
        paras['acl'] = args['a']
        paras['path'] = args['f']
        ret = self.ha.callGetLocalFunc("ntacllib", paras)
        return ret

def main():
    nt = ntacl()
    print nt.do_ntacl(sys.argv[1:])
    
if __name__ == "__main__":
    main()
