#!/usr/bin/env python
# -*- coding: utf-8 -*- 
import traceback
import os
import sys
import commands
import re
import base64
import pexpect
import pwd
import copy
import grp


def debug_user(HA, msg):
	try:
		HA.log(0, "[restoreUser] %s"%msg)
	except:
		print "[restoreUser]", msg

def upgrade_ha_usergroup(HAServer, paraList):
	os.system("/usr/bin/net groupmap add ntgroup='users' unixgroup='users' rid=200000 type=local") 

def restoreUser(HAServer, paraList=None):
	try:
		upgrade_ha_usergroup(HAServer, paraList)
		status = 0
		para_config = {}
		para_config['controller'] = "A"
		para_config['serviceId'] = "0"
				
		ret = _restore_user(HAServer, para_config)
		
		if ret['status'] != 0:
			status = -1
		
		return {'status': status }
		
	except:
		debug_user(HAServer, traceback.format_exc())
		return {'status' : 999}

def updateSystemUser(config_data):
	ret = False
	systemUser = ['ldap:x:55:55:OpenLDAP server:/var/lib/ldap:/sbin/nologin',
					'squid:x:23:23::/var/spool/squid:/sbin/nologin',
					'named:x:25:25:Named:/var/named:/sbin/nologin',
					'radiusd:x:95:95:radiusd user:/var/lib/radiusd:/sbin/nologin',
					]
	passwd = config_data.get("passwd")
	for user in systemUser:
		if user not in passwd:
			ret  = True
			passwd = user + '\n' + passwd
			config_data['passwd'] = passwd
		
	shadowUser = ['ldap:!!:16993::::::',
					'squid:!!:17073::::::',
					'named:!!:17073::::::',
					'radiusd:!!:17073::::::',
					]
	shadow = config_data.get("shadow")
	for user in shadowUser:
		if user not in shadow:
			ret  = True
			shadow = user + '\n' + shadow
			config_data['shadow'] = shadow
		
	groupList = [
				'squid:x:23:',
				'named:x:25:',
				'radiusd:x:95:',
				]
	group = config_data.get("group")
	for sys_group in groupList:
		if sys_group not in group:
			ret  = True
			group = sys_group + '\n' + group
			config_data['group'] = group
	
	if 'wbpriv:x:88:squid' not in group:
		group = group.replace('wbpriv:x:88:', 'wbpriv:x:88:squid')
		config_data['group'] = group

	if '+:::' not in group:
		group = group + '+:::' + "\n"
		config_data['group'] = group	

	return ret

def updateHomePath(HAServer, config_data):
	try:
		passwd = config_data.get("passwd")
		userlist = passwd.split('\n')
		homelist = []
		for i in xrange(len(userlist)):
			user = userlist[i].strip()
			if user != "":
				homelist.append(user.split(":")[5])
		paraList = {}
		paraList['operation'] = 'checkDirectoryValid'
		paraList['pathList'] = homelist
		paraList['controller'] = HAServer.getCurrentController()
		ret = HAServer.callGetLocalFunc('folderOperation', paraList)
		
		for i in xrange(len(ret['data'])):
			status, path = ret['data'][i]
			items = userlist[i].split(":")
			if status == 0:
				items[5] = path
			else:
				items[5] = items[5] if items[5] != "" else "/"
			userlist[i] = (":").join(items)
		config_data['passwd'] = "\n".join(userlist)
		return True
	except:
		HAServer.log(0, '[restoreUser] %s' %(traceback.format_exc()) )
		return False

def read_file(HAServer, fname):
	try:
		with open(fname, "r") as fr:
			data = fr.read()
		return data
	except:
		debug_user(HAServer, traceback.format_exc())
		return ""

def write_file(HAServer, fname, data, etc_data):
	if data and data != etc_data:
		with open(fname, "w") as fw:
			fw.write(data)
		debug_user(HAServer, "write %s"%fname)
	else:
		debug_user(HAServer, "not write %s"%fname)

def get_smb_groups():
	groups = {}
	data = commands.getoutput("net groupmap list").splitlines()
	for line in data:
		line = line.strip()
		items = line.split()		
		groups[items[0].strip()] = True
	return groups

def get_local_groups():
	groups = []
	with open("/etc/group", "r") as fr:
		data = fr.readlines()
		for line in data:
			items = line.split(":")
			if items[0] == "+":
				continue
			groups.append([items[0], int(items[2])])		
	return groups	

def cmd_add_smbgroup(groupname):
	gid = grp.getgrnam(groupname).gr_gid		
	cmd = "/usr/bin/net groupmap add ntgroup='%s' unixgroup='%s' rid=%d type=local"%(groupname,groupname, gid + 100000)
	result = os.system(cmd)

def cmd_delete_smbgroup(groupname):
	cmd = "/usr/bin/net groupmap delete ntgroup='%s'"%groupname
	os.system(cmd)

def restore_smb_groups():
	smbgroups_dic = get_smb_groups()				
	localgroups_list = get_local_groups()			
	for groupname, gid in localgroups_list:
		if gid < 100000:
			continue
		if smbgroups_dic.has_key(groupname):
			continue
		cmd_add_smbgroup(groupname)

def _restore_user(HAServer, para_config):
	try:
		config_data = HAServer.getConfig("UserConfig", "getUserConfig", para_config).get('data')
		home_ret = updateHomePath(HAServer, config_data)
		update_ret = updateSystemUser(config_data)
		if update_ret != True and home_ret != True:	
			#check md5sum of files
			md5Config= HAServer.getConfig("UserConfig", "getMD5", para_config).get('data')
			passwd_md5 = commands.getoutput("md5sum /etc/passwd").split()[0]
			shadow_md5 = commands.getoutput("md5sum /etc/shadow").split()[0]
			group_md5 = commands.getoutput("md5sum /etc/group").split()[0]
			if passwd_md5 == md5Config.get("passwd") and shadow_md5 == md5Config.get("shadow") and group_md5 == md5Config.get("group"):
				return {'status': 0 }
		
		for fname in ['passwd', 'shadow', 'group']:
			data = config_data.get(fname)
			etc_data = read_file(HAServer, "/etc/%s"%fname)
			write_file(HAServer, "/etc/%s"%fname, data, etc_data)
		
		#restore Samba User
		smb_data = HAServer.getConfig("UserConfig", "getSmbUserConfig", para_config).get('data')
		cmd = 'net getlocalsid'
		SID = commands.getoutput(cmd).split(':')[1].strip()
		for username,hashpasswd in smb_data.iteritems():
			try:
				# add samba user
				password = base64.b64decode(hashpasswd[0])
				
				child = pexpect.spawn('/usr/bin/smbpasswd -c /etc/samba/smb.conf.default -a %s'%username)
				child.expect('New SMB password:', timeout=10)
				child.sendline(password)
				child.expect('Retype new SMB password:', timeout=10)
				child.sendline(password)
				child.expect(pexpect.EOF)
				
				#set SID & RID
				uid = pwd.getpwnam(username).pw_uid
				cmd = '/usr/bin/pdbedit -u "%s" -U "%s"-"%s" -f ""'%(username,SID,uid)
				os.system(cmd)
				
			except:
				debug_user(HAServer, traceback.format_exc())
				return {'status' : 999}
		
		restore_smb_groups()
		#set iftsup unlock
		cmd = 'passwd -u iftsup'
		os.system(cmd)
		
		HAServer.setInfo("UserInfo", "updateInfo")
		return {'status': 0 }
	except:
		debug_user(HAServer, traceback.format_exc())
		return {'status' : 999}
		
def test_restoreUser(HA):
	restoreUser(HA)

def test_delete_smb_groups(HA):
	smbgroups_dic = get_smb_groups()
	for key in smbgroups_dic.keys():
		cmd_delete_smbgroup(key)	

def test_restore_smb_group(HA):
	restore_smb_groups()

if __name__ == "__main__":
	try:
		sys.path.append("/usr/local/NAS/misc/HAAgent")
		from NASHAComm import *
		HA = NASHAComm("127.0.0.1")
		func = getattr(sys.modules[__name__], sys.argv[1])	
		func(HA)
	except:
		print traceback.format_exc()
	finally:
		HA.closeSocket()
