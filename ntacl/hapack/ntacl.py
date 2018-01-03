import cmd
import traceback
import shlex

from HADefine import *
from NASHAComm import *
import sys
sys.path.append("/var/apache/tomcat/webapps/NAS/misc/HAAgent/")
sys.path.append(WEB_ROOT+"misc/Cmd/CmdTool/")
from cmdtool import *
import argparse

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
        self.parser_ntacl_setown.add_argument("-z", nargs="?", required=True)

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
        self.cmd_log = cmd_log()
        self.ha = None
        self.parsers = NTACLParser()

    @complete_twolevel
    def complete_ntacl(self, args):
        pass

    @print_cmd_manual
    def man_ntacl(self, args):
        pass

    @print_cmd_usage
    def help_ntacl(self, args):
        pass

    @print_cmd_postcmd
    def postcmd(self, stop, line):
        """
            If you want to stop the console, return something that evaluates to .
            If you want to do some post command processing, do it here.
        """
        return stop

    @require_ha_server
    def do_ntacl(self, args, HA=None):
        self.ha = HA
        ret = {'status': SYS_SUCCESSFUL}
        try:
            args_list = shlex.split(args)
            cmd, namespace = self.parsers.find(args_list)
            func_name = "cmd_" + cmd
            ret = self.adapter_cmd(namespace, func_name)
        except:
            print traceback.format_exc()
            ret = {'status': CMD_UNKNOWN_PARAM}
        finally:
            return ret

    @check_ctrl_parameter
    def adapter_cmd(self, args, func_name):
        ret = getattr(self, func_name)(args)
        if ret['status'] == 0:
            ret['status'] = "SYS_SUCCESSFUL"
        else:
            return {'status' : 'SYS_FAILED'}
        return ret

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
        paras['controller'] = args['ctrl']
        paras['serviceId'] = args['wwn']
        ret = self.ha.callGetLocalFunc("ntacllib", paras)
        print ret
        return ret

    def cmd_ntacl_set(self, args):
        paras = {}
        paras['op'] = "ntacl_lib_set"
        paras['acl'] = args['a']
        paras['path'] = args['f']
        paras['controller'] = args['ctrl']
        paras['serviceId'] = args['wwn']
        ret = self.ha.callGetLocalFunc("ntacllib", paras)
        print ret
        return ret

    def cmd_ntacl_setown(self, args):
        print "cmd_ntacl_setown"
        paras = {}
        paras['op'] = "ntacl_lib_setown"
        paras['uid'] = args['o']
        paras['path'] = args['f']
        paras['controller'] = args['ctrl']
        paras['serviceId'] = args['wwn']
        ret = self.ha.callGetLocalFunc("ntacllib", paras)
        return ret

    def cmd_ntacl_replace(self, args):
        print "cmd_ntacl_replace"
        paras = {}
        paras['op'] = "ntacl_lib_replace"
        paras['acl'] = args['a']
        paras['path'] = args['f']
        paras['controller'] = args['ctrl']
        paras['serviceId'] = args['wwn']
        print paras
        ret = self.ha.callGetLocalFunc("ntacllib", paras)
        return ret
