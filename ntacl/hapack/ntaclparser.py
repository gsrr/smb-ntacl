import argparse

class NTACLParser:
    def __init__(self):
        self.cmds = ['ntacl_test']
        self.parser_ntacl = argparse.ArgumentParser(prog="ntacl", add_help=False)
        self.parser_ntacl_test = argparse.ArgumentParser(prog="ntacl_test", add_help=False)
        self.parser_ntacl_test.add_argument("-z", nargs="?", required=True)

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
