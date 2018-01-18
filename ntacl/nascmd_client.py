import socket
import sys
import time
import struct
import binascii
import os
import datetime
from argparse import *
import ssl

SSL_ENABLE = False
CLI_MAGIC = 0x0000FAAF
CLI_MAGIC_SSL = 0x0000AFFA


class Client:
	def __init__(self, ssl_enable = False):
		if ssl_enable == True:
			self.init_ssl_socket()
		else:
			self.init_nossl_socket()

	def init_ssl_socket(self):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s = ssl.wrap_socket(self.s, cert_reqs=ssl.CERT_NONE)
		self.s.connect(("localhost", 6101))
		
	def init_nossl_socket(self):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect(("localhost", 6100))
		
	def dispatch(self, cmd):
		func = getattr(self, cmd)
		ret = func()
		return ret

	def send(self, cmd):
		self.s.send(cmd)
		rep_packet = self.s.recv(16)
		rep_header = struct.unpack("4I", rep_packet)
		rep_magic = int(rep_header[0])
		rep_id = int(rep_header[1])
		rep_length = int(rep_header[2])
		rep_res = int(rep_header[3])
		rep_data = self.s.recv(rep_length - 16)
		print rep_header
		print rep_data
		return (rep_header, rep_data)
		
def parser_init():
	parser = ArgumentParser(
		prog='nascmd', 
		add_help=False, 
	)
	parser.add_argument(
		'-f', 
		default=None, 
		dest='file', 
	)
	parser.add_argument(
		'-o', 
		default=None, 
		dest='output', 
	)
	parser.add_argument(
		'-i', 
		action='store_true',
		dest='interactive_mode', 
	)
	parser.add_argument(
		'-c', 
		default=None, 
		dest='command', 
	)
	parser.add_argument(
		'--ssl', 
		action='store_true',
		dest='ssl_enable', 
	)
	parser.add_argument(
		'--test', 
		action='store_true',
		dest='unitest', 
	)
	return parser

def exec_interactive_mode():
	cli = Client(SSL_ENABLE) 
	while True:
		print "client>> ", 
		cli_magic = CLI_MAGIC
		cli_reqid = 1234
		cmd = sys.stdin.readline()
		cmd = cmd.strip()
		if cmd == "" or cmd == "exit":
			break
		cli_length = len(cmd) + 16
		cli_res = 0
		header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
		cli.send(header + cmd.strip())
	
def exec_command_mode(cmd):
	cli = Client(SSL_ENABLE) 
	cli_magic = CLI_MAGIC
	cli_reqid = 1234
	cli_length = len(cmd) + 16
	cli_res = 0
	header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
	cli.send(header + cmd.strip())

def exec_file_mode(infile, outfile):
	fw = None
	if outfile != None:
		if os.path.exists(outfile):
			os.remove(outfile)
		fw = open(outfile, "a")
	cli = Client(SSL_ENABLE) 
	cli_magic = CLI_MAGIC
	cli_reqid = 1234
	cli_res = 0
	with open(infile, "r") as fr:
		lines = fr.readlines()
		for line in lines:
			line = line.strip()
			if line == "" or line.startswith("#"):
				continue
			cli_length = len(line) + 16
			header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
			print "%s,%s\n"%(struct.unpack("4I", header), line)
			rep_header, rep_data = cli.send(header + line)
			if fw != None:
				time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
				fw.write("[%s] %s,%s\n"%(time_str, struct.unpack("4I", header), line))
				fw.write("[%s] %s,%s\n"%(time_str, rep_header, rep_data))
	if fw != None:
		fw.close()

def test_execcmd():
	cmd = "ha status -z a@0"
	cli = Client(SSL_ENABLE) 
	cli_magic = CLI_MAGIC
	cli_reqid = 1234
	cli_length = len(cmd) + 16
	cli_res = 0
	header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
	cli.send(header + cmd.strip())
	
def test_ssl_execcmd():
	cmd = "ha status -z a@0"
	cli = Client(True) 
	cli_magic = CLI_MAGIC
	cli_reqid = 1234
	cli_length = len(cmd) + 16
	cli_res = 0
	header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
	cli.send(header + cmd.strip())

def test_execcmd_badmagic():
	cmd = "ha status -z a@0"
	cli = Client(SSL_ENABLE) 
	cli_magic = 0xAFFD0000
	cli_reqid = 1234
	cli_length = len(cmd) + 16
	cli_res = 0
	header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
	cli.send(header + cmd.strip())
	

def test_execcmd_unknow():
	cmd = "aabb test -z a@0"
	cli = Client(SSL_ENABLE) 
	cli_magic = CLI_MAGIC
	cli_reqid = 1234
	cli_length = len(cmd) + 16
	cli_res = 0
	header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
	cli.send(header + cmd.strip())

def test_ssl_execcmd_badmagic():
	cmd = "ha status -z a@0"
	cli = Client(True) 
	cli_magic = 0xAFDA0000
	cli_reqid = 1234
	cli_length = len(cmd) + 16
	cli_res = 0
	header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
	cli.send(header + cmd.strip())

def test_ssl_execcmd_multi():
	cmd = "multicmd \"ha status -z a@0\" \"ha status -z a@0\""
	cli = Client(True) 
	cli_magic = CLI_MAGIC_SSL
	cli_reqid = 1234
	cli_length = len(cmd) + 16
	cli_res = 0
	header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
	cli.send(header + cmd.strip())

def test_ssl_execcmd_multierror():
	cmd = "multicmd \"ha status -z a@0\" \"ha status -z @0\""
	cli = Client(True) 
	cli_magic = CLI_MAGIC_SSL
	cli_reqid = 1234
	cli_length = len(cmd) + 16
	cli_res = 0
	header = struct.pack("4I",cli_magic, cli_reqid, cli_length, cli_res)
	cli.send(header + cmd.strip())

def exec_unitest_mode():
	func_list = dir(sys.modules[__name__])
	for func in func_list:
		if func.startswith("test_"):
			print func
			getattr(sys.modules[__name__], func)()

def main():
	global SSL_ENABLE
	parser = parser_init()
	paras = parser.parse_args(sys.argv[1:]).__dict__
	if paras['ssl_enable'] == True:
		SSL_ENABLE = True
	if paras['interactive_mode'] == True:
		exec_interactive_mode() 
		sys.exit(0)
	if paras['unitest'] == True:
		exec_unitest_mode() 
		sys.exit(0)
	elif paras['command'] != None:
		exec_command_mode(paras['command'])
		sys.exit(0)
	elif paras['file'] != None:
		exec_file_mode(paras['file'], paras['output'])
		sys.exit(0)
		

if __name__ == "__main__":
	main()


