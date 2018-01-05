# -*- coding: utf-8 -*-
from subprocess import *
from copy import deepcopy
import sys
import traceback
sys.path.append("/usr/local/NAS/misc/")
import os
import pexpect
import commands
import pwd
import grp
import copy
import time
import datetime
import csv
import StringIO
import zipfile
import threading
import shutil
import base64

sys.path.append("/usr/local/NAS/misc/HAAgent/Lib")
from tool import *
sys.path.append("/usr/local/NAS/misc/agent/python/user_auth")
from pam import ift_authenticate

#sys.path.append("/usr/local/NAS/misc/HAAgent/Lib/Storage")
#from createVolume import createFileSystem

Version = 2

def execute(cmd):
	try:
		if isinstance(cmd,list):
			p = Popen(cmd,shell=False,stderr=PIPE,stdout=PIPE)
		elif isinstance(cmd,str):
			p = Popen(cmd,shell=True,stderr=PIPE,stdout=PIPE)
		else:
			raise
		(out,err) = p.communicate()
		returncode = p.returncode
		return (returncode,out.strip(),err.strip())
	except:
		return (-1,'','exception')

import iftsyslog
def log(msg='', level=iftsyslog.LOG_INFO):
	iftsyslog.log("userOperation", level, msg)

	
def getpwuid(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff, 'data':paraList}
	try:
		user = pwd.getpwuid(paraList.get("uid"))
		return {'status':0,'data':user}
	except:
		return {'status':-1}

def getpwnam(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff, 'data':paraList}
	try:
		user = pwd.getpwnam(paraList.get("name"))
		return {'status':0,'data':user}
	except:
		return {'status':-1}
		
def getpwall(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff, 'data':paraList}
	try:
		userlist = pwd.getpwall()
		return {'status':0,'data':userlist}
	except:
		return {'status':-1}
		
def getgrgid(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff, 'data':paraList}
	try:
		user = grp.getgrgid(paraList.get("uid"))
		return {'status':0,'data':user}
	except:
		return {'status':-1}

def getgrnam(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff, 'data':paraList}
	try:
		user = grp.getgrnam(paraList.get("name"))
		return {'status':0,'data':user}
	except:
		return {'status':-1}
		
def getgrall(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff, 'data':paraList}
	try:
		userlist = grp.getgrall()
		return {'status':0,'data':userlist}
	except:
		return {'status':-1}
		
def getUIDbyName(name):
	try:
		user = pwd.getpwnam(name)
		return user.pw_uid
	except:
		return -1


def editUser(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		HAServer.setConfig("UserConfig", "updateConfig", paraList)
		return {'status': 0xff}
	username = paraList.get('username')
	password = paraList.get('password')
	description = paraList.get('description')
	groups = paraList.get('groups')
	userhome = paraList.get('userhome')
	superuser = paraList.get('superuser')
	priGroup = groups[0]
	tmpGroups = copy.deepcopy(groups)
	tmpGroups.remove(priGroup)
	secGroup = ",".join(tmpGroups)
	passwdExpireDay = paraList.get('passwdExpireDay')
	ctrl = paraList.get('controller')
	wwn = paraList.get('serviceId')
	
	if userhome:
		pathList = userhome.split('/')
		folderpath = '/'+pathList[1]+'/'+pathList[2]
		retA = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getGeneralFolders', 'controller': 'A'}, logLevel = 2)
		folderListA = retA['data']
		retB = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getGeneralFolders', 'controller': 'B'}, logLevel = 2)
		folderListB = retB['data']
		folderList = folderListA + folderListB
		
		
	if userhome == '' or os.path.realpath(folderpath) in [folder['directory'] for folder in folderList]:
		userhomeArg = '-d "%s"'%userhome if userhome else ''
		cmd = '/usr/sbin/usermod %s -g "%s" -G "%s" %s "%s"'%(userhomeArg,priGroup,secGroup,'-c %s'%shellOct(description),username)
		
		(ret,out,err) = executeGetStatus(cmd)
		if ret != 0:
			return {'status':ret,'msg':'useredit error','out':''.join(out),'err':''.join(err)}
		
		if superuser:
			addUserToRootGroup(username)
			HAServer.sysLog(LOG_LEVEL_INFO, "Account-User", "superuser_privilege_assign", [username])
		else:
			removeUserFromRootGroup(username)
			HAServer.sysLog(LOG_LEVEL_INFO, "Account-User", "superuser_privilege_stop", [username])
		'''
		if password != '######':
			ret = changeUserPasswd(HAServer,paraList)
			if ret["status"] != 0:
				return ret
		'''
		if userhome:
			if HAServer.getCurrentController() == 'A':
				homeList = folderListA
			else:
				homeList = folderListB
			if os.path.realpath(folderpath) in [folder['directory'] for folder in homeList]:
				if not os.path.exists(userhome):
					ret = createUserHome(HAServer, paraList)
					ret = shareUserHome(HAServer, paraList)
				uid = getUIDbyName(username)
				user = pwd.getpwuid(uid)
				os.chown(userhome,uid,user.pw_gid)
			else:
				pass
		
		if passwdExpireDay:
			(ret,out,err) = executeGetStatus("passwd -x %s '%s'"%(passwdExpireDay, username))
			(ret,out,err) = executeGetStatus("/usr/bin/pdbedit -u '%s' -E %s"%(username, passwdExpireDay))
			
		if secGroup:
			HAServer.sysLog(LOG_LEVEL_INFO, "Account-User", "user_assign_group", [username, secGroup])
		
		res = HAServer.setConfig("UserConfig", "updateConfig", paraList)
		res = HAServer.setInfo("UserInfo","updateInfo")
		
	else:
		return {'status':1,'data':'user home not exist'}
	return {'status':0}

def changeUserPasswd(HAServer, paraList):
	username = paraList.get('username')
	hashpasswd = paraList.get('password')
	password = base64.b64decode(hashpasswd)
	
	if password != '######':
		ret = changePassword(username,password)
		if ret != 0:
			{'status':ret}

	paraListA = {}
	paraListA['operation'] = 'saveHistory'
	paraListA['username'] = username
	paraListA['password'] = password
	paraListA['controller'] = paraList.get('controller')
	paraListA['serviceId'] = paraList.get('serviceId')
	HAServer.callGetLocalFunc("passwdManage", paraListA, logLevel=2)
	
	paraList2 = {
		'op' : 'mschap_modifyuser',
		'user' : username,
		'passwd' : password,
		'controller' : paraList.get('controller'),
		'serviceId' : paraList.get('serviceId')
	}
	
	if Version >=2:
		ret = HAServer.callGetLocalFunc("vpnLib", paraList2)
	
	HAServer.setInfo("UserInfo", "updateInfo")
	res = HAServer.setConfig("UserConfig", "changeUserPW", paraList)
	HAServer.sysLog(LOG_LEVEL_INFO, "passwdManage", "passwd_changed", [username])
	#logToSystem(LOG_LEVEL_INFO, c_char_p("passwdManage"), c_char_p("passwd_changed %s__@@__%s" %(username, role)), HAServer)
	return {'status':0}

def changePassword(username, password):
	try:
		child = pexpect.spawn('passwd %s'%username)
		child.expect('New password:', timeout=10)
		child.sendline(password)
		child.expect('Retype new password:', timeout=10)
		child.sendline(password)
		child.expect(pexpect.EOF)
		return 0
	except:
		return 1

def getPasswdHistory(HAServer, paraList):
	try:
		ret = HAServer.getConfig("UserConfig", "getSmbUserConfig", paraList)
		return ret
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status': -1}

def lockUser(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xf}
	try:
		username = paraList.get('username')
		lock = '-l' if paraList.get('lock') else '-u'
		cmd = 'passwd %s %s' %(lock, username)
		(ret,out,err) = executeGetStatus(cmd)
		if ret != 0:
			HAServer.log(1, '>> [userOperation] %s'%(str(out)))
			return {'status':result,'msg':'lock,unlock user fail','out':''.join(out),'err':''.join(err)}
		HAServer.setInfo("UserInfo", "updateInfo")
		HAServer.setConfig("UserConfig", "updateConfig", paraList)
		return {'status': 0}
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}

def addUserToRootGroup(username):
	tmp = commands.getoutput('cat /etc/group | grep "^root:"').split(':')
	if tmp[3] == '':
		tmp[3] = username
	else:
		userList = tmp[3].split(',')
		if username in userList:
			return
		userList.append(username)
		tmp[3]=','.join(userList)
	os.system('sed -i "s/^root:.*/%s/g" /etc/group'%(':'.join(tmp)))

def removeUserFromRootGroup(username):
	tmp = commands.getoutput('cat /etc/group | grep "^%s:"'%'root').split(':')
	if tmp[3] == '':
		return
	userList = tmp[3].split(',')
	if not username in userList:
		return
	userList.remove(username)
	tmp[3]=','.join(userList)
	os.system('sed -i "s/^%s:.*/%s/g" /etc/group'%('root',':'.join(tmp)))


def shellOct(s):
	return "$'%s'"%"".join(['\%o'%ord(c) for c in s])

def createUser(HAServer, paraList):
	username = paraList.get('username')
	hashpasswd = paraList.get('password')
	password = base64.b64decode(hashpasswd)
	description = paraList.get('description')
	groups = paraList.get('groups')
	userhome = paraList.get('userhome')
	superuser = paraList.get('superuser')
	userid = paraList.get('userid')
	passwdExpireDay = paraList.get('passwdExpireDay')
	passwdWarnDay = paraList.get('passwdWarnDay')
	ctrl = paraList.get('controller')
	wwn = paraList.get('serviceId')

	priGroup = groups[0]
	tmpGroups = copy.deepcopy(groups)
	tmpGroups.remove(priGroup)
	secGroup = ",".join(tmpGroups)

	#create user
	if userhome:
		pathList = userhome.split('/')
		#poolname = pathList[1]
		folderpath = '/'+pathList[1]+'/'+pathList[2]
		ret = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getGeneralFolders', 'controller': 'A'}, logLevel = 2)
		folderList = ret['data']
		retB = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getGeneralFolders', 'controller': 'B'}, logLevel = 2)
		folderListB = retB['data']
		folderList.extend(folderListB)

	if userhome == '' or os.path.realpath(folderpath) in [folder['directory'] for folder in folderList]:
		
		if userid == '':
			if not userhome:
				cmd = '/sbin/useradd -M -g "%s" -G "%s" -s "/bin/nassh" %s "%s"'%(priGroup,secGroup,"-c %s"%shellOct(description),username)
			else:
				cmd = '/sbin/useradd -d "%s" -g "%s" -G "%s" -s "/bin/nassh" %s "%s"'%(userhome,priGroup,secGroup,"-c %s"%shellOct(description),username)
		else:
			if not userhome:
				cmd = '/sbin/useradd -M -u "%s" -g "%s" -G "%s" -s "/bin/nassh" %s "%s"'%(userid,priGroup,secGroup,"-c %s"%shellOct(description),username)
			else:
				cmd = '/sbin/useradd -d "%s" -u "%s" -g "%s" -G "%s" -s "/bin/nassh" %s "%s"'%(userhome,userid,priGroup,secGroup,"-c %s"%shellOct(description),username)
		(ret,out,err) = executeGetStatus(cmd)
		if ret == 12:
			pass
		elif ret != 0:
			return {'status':ret,'data':'useradd error','out':''.join(out),'err':''.join(err)}
		uid = getUIDbyName(username)
		
		if not userhome:
			userbase = pwd.getpwnam(username)
			temp = re.sub(userbase.pw_dir, '/', open('/etc/passwd', 'r').read())
			open('/etc/passwd', 'w').write(temp)
		else:
			if os.path.exists(userhome):
				cmd1 = 'rm %s/.bash_logout' %userhome
				os.system(cmd1)
				cmd2 = 'rm %s/.bash_profile' %userhome
				os.system(cmd2)
				cmd3 = 'rm %s/.bashrc' %userhome
				os.system(cmd3)
				user = pwd.getpwuid(uid)
				os.chown(userhome,uid,user.pw_gid)
		
		#ret,out,err = execute(['/usr/sbin/smbadm','enable-user',username])	#smb/server
		#log([ret,out,err])
		'''
		ret,out,err = execute(['/usr/bin/pdbedit','-L',])
		if ret != 0:
			os.system("systemctl start ctdb")
			log("start ctdb")
		'''
		cmd = 'net getlocalsid'
		SID = commands.getoutput(cmd).split(':')[1].strip()
		ret,out,err = execute(['/usr/bin/smbpasswd','-an',username, '-c', '/etc/samba/smb.conf.default'])	#samba
		#log([ret,out,err])
		cmd = '/usr/bin/pdbedit -u "%s" -U "%s"-"%s" -f ""'%(username,SID,uid)
		ret,out,err = execute(cmd)	#set SID & RID , remove full name
		#log([ret,out,err])
		
		if changePassword(username, password) != 0:
			HAServer.log(1, "createUser change passwd failed")
		
		if superuser:
			addUserToRootGroup(username)
			HAServer.sysLog(LOG_LEVEL_INFO, "Account-User", "superuser_privilege_assign", [username])
		
		if passwdExpireDay:
			(ret,out,err) = executeGetStatus("passwd -x %s '%s'"%(passwdExpireDay, username))
			(ret,out,err) = executeGetStatus("/usr/bin/pdbedit -u '%s' -E %s"%(username, passwdExpireDay))
		if passwdWarnDay:
			(ret,out,err) = executeGetStatus("passwd -w %s '%s'"%(passwdWarnDay, username))
			
		if secGroup:
			HAServer.sysLog(LOG_LEVEL_INFO, "Account-User", "user_assign_group", [username, secGroup])
			
		HAServer.callGetLocalFunc("passwdManage", {"operation":"saveHistory","username":username, "password":password,"controller":ctrl,"serviceId":wwn}, logLevel=2)
		res = HAServer.setConfig("UserConfig", "addUserConfig", paraList)
		res = HAServer.setInfo("UserInfo","updateInfo")
		return {'status':0,'uid':uid}
	else:
		return {'status':1,'data':'user home not exist'}
	
	

def addUser(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		HAServer.setConfig("UserConfig", "addUserConfig", paraList)
		return {'status': 0xff}
	username = paraList.get('username')
	password = paraList.get('password')
	description = paraList.get('description')
	groups = paraList.get('groups')
	userhome = paraList.get('userhome')
	superuser = paraList.get('superuser')
	userid = paraList.get('uid')
	passwdExpireDay = paraList.get('passwdExpireDay')
	passwdWarnDay = paraList.get('passwdWarnDay')
	ctrl = paraList.get('controller')
	wwn = paraList.get('serviceId')
	#create user home
	#if userhome:
	#	ret = createUserHome(HAServer, paraList)
		
	paraList2 = {}
	paraList2['username'] = username
	paraList2['password'] = password
	paraList2['description'] = description
	paraList2['groups'] = groups
	paraList2['userhome'] = userhome
	paraList2['superuser'] = superuser
	paraList2['userid'] = userid
	paraList2['passwdExpireDay'] = passwdExpireDay
	paraList2['passwdWarnDay'] = passwdWarnDay
	paraList2['operation'] = 'createUser'
	paraList2['controller'] = ctrl
	paraList2['serviceId'] = wwn
	ret2 = HAServer.callGetLocalFunc("userOperation", paraList2, logLevel=2)
	
	if ret2.get('status') != 0:
		ret2['func'] = "createUser"
		return ret2
	else:
		uid = ret2.get('uid')
		
	paraList3 = {
		'op' : 'mschap_adduser',
		'user' : username,
		'passwd' : base64.b64decode(password),
		'controller' : ctrl,
		'serviceId' : wwn
	}
	
	if Version >=2:
		ret = HAServer.callGetLocalFunc("vpnLib", paraList3)
		
	if os.path.exists(userhome):
		if userhome:
			#user = pwd.getpwuid(uid)
			#os.chown(userhome,uid,user.pw_gid)
			ret3 = shareUserHome(HAServer, paraList)
			if ret3["status"] == 99:
				return ret3
	
	HAServer.sysLog(LOG_LEVEL_INFO, "Account-User", "user_create", [username])
	return ret2
	
def checkUserLower(HAServer, paraList):
	ret = {'status': 0}
	try:
		username = paraList.get('username').lower()
		
		for user in open('/etc/passwd','r'):
			if len(user.strip()) == 0:
				continue
			tmp = user.split(':')
			
			uid = int(tmp[2])
			if uid < 1000 or uid == 60002 or uid == 65534:
					continue
			
			if tmp[0].lower() == username:
				ret = {'status': 1,'data':'username exist'}
	except:
		HAServer.log(1, '>> [userOperation] error read => %s'%(str(line)))
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		ret = {'status': -1}
		
	finally:
		return ret
	
def checkUserExist(HAServer, paraList):
	username = paraList.get('username')
	userInfo = HAServer.getLocalInfo("UserInfo").get('data')
	ret = {'status': 0}
	
	#for line in userInfo.passwd.splitlines():
	#	if line.split(':')[0] == username:
	#		ret = {'status': 1,'data':'username exist'}
	#		break
	userInfos = userInfo.passwd.splitlines()
	tmpNameList = []
	for info in userInfos:
		tmpNameList.append(info.split(':')[0])
	revNameList = tmpNameList[:25]
	usedNameList = tmpNameList[25:]
	if username in revNameList:
		revNames = '\n'.join(revNameList)
		ret = {'status': 3,'data': revNames}
	if username in usedNameList:
		ret = {'status': 1,'data':'username exist'}
	return ret

def checkGroupExist(HAServer, paraList):
	groupname = paraList.get('groupname')
	userInfo = HAServer.getLocalInfo("UserInfo").get('data')
	ret = {'status': 0}
	
	#for line in userInfo.passwd.splitlines():
	#	if line.split(':')[0] == username:
	#		ret = {'status': 1,'data':'username exist'}
	#		break
	userInfos = userInfo.group.splitlines()
	revNameList = []
	usedNameList = []
	for info in userInfos:
		tokens = info.strip().split(':')
		if len(tokens) > 2:
			gid = int(tokens[2])
			if gid == 100 or (gid >= 1000 and gid <= 1000000):
				usedNameList.append(tokens[0])
			else:
				revNameList.append(tokens[0])
	if groupname in revNameList:
		revNames = '\n'.join(revNameList)
		ret = {'status': 3,'data': revNames}
	if groupname in usedNameList:
		ret = {'status': 1,'data':'username exist'}
	return ret

def checkAdUserHomeExist(HAServer, paraList):
	userhome = paraList.get('userhome')
	ret = {'status': 0}
	if os.path.exists(userhome):
		return {'status': 1,'data':'userhome exist'}
	return ret

def checkUserHomeExist(HAServer, paraList):
	userhome = paraList.get('userhome')
	ret = {'status': 0}
	
	if os.path.exists(userhome):
		ret = {'status': 1,'data':'userhome exist'}
		return ret
	return ret
	
def removeExistUserHome(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		ret = {'status': 0xf}
		return 
	userhome = paraList.get('userhome')
	ret = {'status': 0}
	try:
		if userhome:
			if os.path.exists(userhome):
				shutil.rmtree(userhome)
			else:
				ret = {'status': 0}
		else:
			ret = {'status': -1}
	except:
		ret = {'status': -1}
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
	finally:
		return ret
	
def createUserHome(HAServer, paraList):
	ret = {'status': 0, 'data': ''}
	try:
		userhome = paraList.get('userhome')
		if userhome:
			(result,out,err) = executeGetStatus('/bin/mkdir -p %s'%userhome) 
			if result != 0:
				return {'status':result,'data': 'createUserHome fail'}
			(result,out,err) = executeGetStatus('/bin/chmod 700 %s'%userhome)
	except:
		ret = {'status': 1, 'data': 'createUserHome exception'}
	finally:
		return ret

def shareUserHome(HAServer, paraList):
	ret = {'status': 0, 'data': ''}
	try:
		ctrl = paraList.get('controller')
		wwn = paraList.get('serviceId')
		username = paraList.get('username')
		userhome = paraList.get('userhome')
		if userhome:
			paraList2 = {}
			userHome_old = pwd.getpwnam(username).pw_dir
			paraList2['operation'] = 'deleteShare'
			paraList2['path'] = userHome_old
			paraList2['CIFS'] = True
			paraList2['FTP'] = True
			paraList2['SFTP'] = True
			paraList2['notEventlog'] = True
			paraList2['controller'] = ctrl
			paraList2['serviceId'] = wwn
			res = HAServer.callGetLocalFunc("shareOperation", paraList2)
			
			homeName = userhome.strip('/').split('/')[-1]
			paraList3 = {}
			paraList3['operation'] = 'addShare'
			paraList3['controller'] = ctrl
			paraList3['serviceId'] = wwn
			paraList3['path'] = userhome
			paraList3['CIFS'] = True
			paraList3['FTP'] = True
			paraList3['SFTP'] = True
			paraList3['sharename'] = homeName
			ret = HAServer.callGetLocalFunc('shareOperation', paraList3)
	except:
		ret = {'status': 1, 'data': 'shareUserHome exception'}
	finally:
		return ret

def deleteUser(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		HAServer.setConfig("UserConfig", "deleteUserConfig", paraList)
		return {'status': 0xff}
	ret = {'status': 0}
	username = paraList.get('username')
	
	# delete user quota
	entryList = []
	retobj = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getGeneralFolders', 'controller': HAServer.getCurrentController()} , logLevel=2)
	folderList = retobj['data'] if retobj['status'] == 0 else []
	
	for folder in folderList:
		tokens = folder['directory'].strip('/').split('/')
		folder_pair = (tokens[0], tokens[1])
		limit = [(username, 0)]
		entryList.append((folder_pair, limit))
	
	paraList4 = {}
	paraList4['entryList'] = entryList
	paraList4['operation'] = 'setUserGroupQuota'
	paraList4['quotatype'] = 'user'
	paraList4['controller'] = HAServer.getCurrentController()
	ret = HAServer.callGetLocalFunc('folderOperation', paraList4)
	
	deleteHome = paraList.get('deleteHome')
	userHome = pwd.getpwnam(username).pw_dir
	
	if userHome != '/':
		paraList2 = {}
		paraList2['operation'] = 'deleteShare'
		paraList2['path'] = userHome
		paraList2['CIFS'] = True
		paraList2['FTP'] = True
		paraList2['SFTP'] = True
		paraList2['controller'] = paraList.get('controller')
		paraList2['serviceId'] = paraList.get('serviceId')
		res = HAServer.callGetLocalFunc("shareOperation", paraList2)
	
	if userHome == '/':
		deleteHome = False
	if deleteHome :
		(result,out,err) = executeGetStatus('userdel -f -r "%s"'%username)
	else :
		(result,out,err) = executeGetStatus('userdel -f "%s"'%username)
	if result != 0:
		return {'status':result,'msg':'delete user fail','out':''.join(out),'err':''.join(err)}
		
	removeUserFromRootGroup(username)
	
	execute(['/usr/bin/pdbedit','-x','-u',username])
	
	paraList3 = {
	"op" : "delete_user",
	'user' : username,
	'controller' : paraList.get('controller'),
	'serviceId' : paraList.get('serviceId') 
	}
	res = HAServer.callGetLocalFunc("ossLib", paraList3)
	
	paraList5 = {
		'op' : 'mschap_deleteuser',
		'user' : username,
		'controller' : paraList.get('controller'),
		'serviceId' : paraList.get('serviceId') 
	}
	
	if Version >=2:
		ret = HAServer.callGetLocalFunc("vpnLib", paraList5)
	
	res = HAServer.setConfig("UserConfig", "deleteUserConfig", paraList)
	res = HAServer.setInfo("UserInfo","updateInfo")
	HAServer.sysLog(LOG_LEVEL_INFO, "Account-User", "user_delete", [username])
	
	return ret

def cmd_add_smbgroup(groupname):
	gid = grp.getgrnam(groupname).gr_gid		
	cmd = "/usr/bin/net groupmap add ntgroup='%s' unixgroup='%s' rid=%d type=local"%(groupname,groupname, gid + 100000)
	result = os.system(cmd)

def cmd_delete_smbgroup(groupname):
	cmd = "/usr/bin/net groupmap delete ntgroup='%s'"%groupname
	os.system(cmd)

def cmd_modify_smbgroup(newname, groupname):
	cmd_delete_smbgroup(groupname)
	cmd_add_smbgroup(newname)

def cmd_add_group(groupname, gid = None):
	if not gid :
		result = os.system('/usr/sbin/groupadd "%s"'%groupname)
	else:
		result = os.system('/usr/sbin/groupadd -g %s "%s"'%(gid,groupname))

	if result != 0:
		return result

	cmd_add_smbgroup(groupname)
	return result	

def cmd_delete_group(groupname):
	result = os.system('groupdel "%s"'%groupname)
	if result != 0:
		return result

	cmd_delete_smbgroup(groupname)
	return result	

def cmd_modify_group(newname, groupname):
	result = os.system('groupmod -n "%s" "%s"'%(newname,groupname))
	if result != 0:
		return result
	cmd_modify_smbgroup(newname, groupname)
	return result

def decor_group(func):
	def wrap_func(HAServer, paraList):
		if HAServer.getCurrentController() != paraList.get('controller'):
			HAServer.setConfig("UserConfig", "updateConfig", paraList)
			return {'status': 0xff}
		ret = func(HAServer, paraList)
		
		if ret['status'] == 0:
			HAServer.setConfig("UserConfig", "setGroupDescription", paraList)
			HAServer.setInfo("UserInfo","updateInfo")
		return ret	
	return wrap_func

@decor_group
def addGroup(HAServer, paraList):
	ret = {'status': 0}
	groupname = paraList.get('groupname')
	gid = paraList.get('gid')
	users = paraList.get('users')
	
	result = cmd_add_group(groupname, gid)
	if result != 0:
		return {'status': result,'data':'add group fail'}
		
	groupline = commands.getoutput('cat /etc/group | grep "^%s:"'%groupname)
	tmp = groupline.split(':')
	tmp[3] = ','.join(users)
	try:
		file = open('/etc/group', 'r')
		etc_group = file.read()
		file.close()
		new_group = etc_group.replace(groupline, ':'.join(tmp))
		file2 = open('/etc/group.tmp', 'w')
		file2.write(new_group)
		file2.close()
		os.rename('/etc/group.tmp', '/etc/group')
	except:
		return {'status': 3,'data':'add users to group fail'}
	HAServer.sysLog(LOG_LEVEL_INFO, "Account-Group", "group_create", [groupname])
	
	return ret

@decor_group
def editGroup(HAServer, paraList):
	ret = {'status': 0}
	groupname = paraList.get('groupname')
	users = paraList.get('users')
		
	groupline = commands.getoutput('cat /etc/group | grep "^%s:"'%groupname)
	tmp = groupline.split(':')
	tmp[3] = ','.join(users)

	try:
		file = open('/etc/group', 'r')
		etc_group = file.read()
		file.close()
		new_group = etc_group.replace(groupline, ':'.join(tmp))
		file2 = open('/etc/group.tmp', 'w')
		file2.write(new_group)
		file2.close()
		os.rename('/etc/group.tmp', '/etc/group')
	except:
		return {'status': 3,'data':'add users to group fail'}
		
	userList = ",".join(paraList.get('add_delete_users'))
	if paraList.get('log_flag'):
		HAServer.sysLog(LOG_LEVEL_INFO, "Account-Group", "group_add_user", [groupname, userList])
	else:
		HAServer.sysLog(LOG_LEVEL_INFO, "Account-Group", "group_remove_user", [groupname, userList])
	
	return ret
	
@decor_group
def modifyGroup(HAServer, paraList):
	ret = {'status': 0}
	groupname = paraList.get('groupname')
	newname = paraList.get('newname') if paraList.get('newname') else groupname
	description = paraList.get('description')
	gid = paraList.get('gid')  # not set
	
	if newname != groupname:
		result = cmd_modify_group(newname, groupname)	
		if result != 0:
			return {'status': 2,'data':'edit group new name fail'}
	return ret
	
@decor_group
def renameGroup(HAServer, paraList):
	ret = {'status': 0}
	groupname = paraList.get('groupname')
	newname = paraList.get('newname')
	
	if newname:
		result = cmd_modify_group(newname, groupname)	
		if result != 0:
			return {'status': 2,'data':'edit group new name fail'}
	return ret
	
@decor_group
def deleteGroup(HAServer, paraList):
	ret = {'status': 0}
	groupname = paraList.get('groupname')
	
	result = cmd_delete_group(groupname)
	if result != 0:
		return {'status':result,'msg':'delete group fail'}
	
	HAServer.sysLog(LOG_LEVEL_INFO, "Account-Group", "group_delete", [groupname])
	return ret
	
MAXUID = 10000000
MINUID = 1000

def validUID(HAServer, paraList):
	uid = paraList.get("uid")
	uidDict = paraList.get("uidDict")
	if type(uid)==str:
		if uid.isdigit():
			uid = int(uid)
		else:
			return {'status':1}
	
	try:
		if uid == 60001 or uid == 60002 or uid == 65534 or uid > MAXUID or uid < MINUID:
			pass
		else:
			if uidDict:
				uidDict[str(uid)]
			else:
				pwd.getpwuid(uid)
			
	except:
		return {'status':0, 'data':True}
	
	return {'status':0, 'data':False}
	
def getNextUID(HAServer, paraList):
	tmpid = MINUID
	try:
		F = open("/var/nas/etc/lastUID", "r")
		tmpid = int(F.readline().strip()) + 1	#uid starts from lastUID + 1
		F.close()
		Users = HAServer.getInfo("UserInfo", "getLocalInfo").get('data').get('users')
		uidDict = {}
		for user in Users:
			uidDict[user.split(':')[2]] = user.split(':')[0]
	except:
		#print "lastUID not found"
		pass
	
	if tmpid <= MAXUID:
		#search from lastUID+1 to MAXUID
		for uid in xrange(tmpid, MAXUID + 2):
			if uid > MAXUID:
				#search from MINUID to lastUID-1
				for id in xrange(MINUID, tmpid - 1):
					if validUID(HAServer, {"uid":id, 'uidDict':uidDict}).get('data'):
						return {'status':0, 'data':id}
			elif validUID(HAServer, {"uid":uid, 'uidDict':uidDict}).get('data'):
				return {'status':0, 'data':uid}
	else:
		for uid in xrange(MINUID, MAXUID + 1):
			if validUID(HAServer, {"uid":uid, 'uidDict':uidDict}).get('data'):
				return {'status':0, 'data':uid}
		
	return {'status':1}

def validGID(HAServer, paraList):
	gid = paraList.get("gid")
	if type(gid)==str:
		if gid.isdigit():
			gid = int(gid)
		else:
			return {'status':1}
	
	try:
		if gid == 60001 or gid == 60002 or gid == 65534 or gid > MAXUID or gid < MINUID:
			pass
		else:
			grp.getgrgid(gid)
	except:
		return {'status':0, 'data':True}
	
	return {'status':0, 'data':False}
	
def getNextGID(HAServer, paraList):
	tmpid = MINUID
	try:
		F = open("/var/nas/etc/lastGID", "r")
		tmpid = int(F.readline().strip()) + 1	#gid starts from lastGID + 1
		F.close()
	except:
		#print "lastGID not found"
		pass
	
	if tmpid <= MAXUID:
		#search from lastGID+1 to MAXUID
		for gid in xrange(tmpid, MAXUID + 2):
			if gid > MAXUID:
				#search from MINUID to lastGID-1
				for id in xrange(MINUID, tmpid - 1):
					if validGID(HAServer, {"gid":id}).get('data'):
						return {'status':0, 'data':id}
			elif validGID(HAServer, {"gid":gid}).get('data'):
				return {'status':0, 'data':gid}
	else:
		for gid in xrange(MINUID, MAXUID + 1):
			if validGID(HAServer, {"gid":gid}).get('data'):
				return {'status':0, 'data':gid}
		
	return {'status':1}

def userLoginCheck(HAServer, paraList):
	username = paraList.get("username")
	password = paraList.get("password")
	ret,out,err = executeGetStatus("/usr/bin/perl /var/nas/bin/login/pam.pl '%s' '%s'"%(username, password))
	if ret == 0:
		uid = out[1]
		return {"status":0, "data":uid}
	elif ret == 1:
		return {"status":1, "msg":"unknown user"}
	elif ret == 2:
		return {"status":2, "msg":"invalid password"}
	else:
		return {'status':1, "msg":ret}
	
def getNetworkUser(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff}
	### Get user quota ###
	retobjA = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getFileSystemData', 'controller':'A'}, logLevel = 2)
	if retobjA.get('status') != 0:
		HAServer.log(1, '>> [userOperation] error read => %s'%("quota A read error"))
		retobjA = {'data':[]}
	retobjB = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getFileSystemData', 'controller':'B'}, logLevel = 2)
	if retobjB.get('status') != 0:
		HAServer.log(1, '>> [userOperation] error read => %s'%("quota B read error"))
		retobjB = {'data':[]}
	
	quotaTable ={}
	fsList = retobjA['data'] + retobjB['data']
	for fsdata in fsList:
		fsname = fsdata['fsname']
		for quotaset in fsdata['quotas']:
			qtype = quotaset['type']		# may be 'user' or 'group'
			if qtype != 'user':
				continue
			for unit in quotaset['units']:
				id = unit['id']
				quota = str(long(unit['block-hard'])*1024)
				used = str(long(unit['block-used'])*1024)
				if quotaTable.has_key(id):
					quotaTable[id].append({'used':used, 'limit':quota, 'path':fsname})
				else:
					quotaTable.update({id:[{'used':used, 'limit':quota, 'path':fsname}]})
	
	### start getting the network users ###
	# 1. Update ldap/ad Info
	networkUsers = []
	ad_status,ldap_status, nis_status = False, False, False
	ret = HAServer.getInfo("ServiceInfo", "getServiceInfo", {"name":['AD', 'LDAP', 'NIS']} )
	if ret.get('status') == 0:
		ad_status = ret.get('data').get('AD').get('enabled')
		ldap_status = ret.get('data').get('LDAP').get('enabled')
		nis_status = ret.get('data').get('NIS').get('enabled')
	
	if ad_status or ldap_status or nis_status:
		updating = False
		Flag = HAServer.getInfo("UserInfo", "getUpdateFlag")
		if Flag.get('status') == 1:
			updating = True
		else:
			res = HAServer.setInfo("UserInfo", "updateNetworkInfo")
		netUser = []
		netUser = HAServer.getInfo("UserInfo", "getNetworkInfo").get("data").get("users")
	else:
		updating = False
		netUser = None
	
	# 2. If ldap/ad service or nis service is enable, load corresponding users
	if netUser is not None:
		try:
			link = commands.getoutput('ls -al /home/ImportedUser').split()[-1]
			para = {'operation':'domainAccountInfo', 'controller': paraList.get('controller') }
			if ad_status or ldap_status :
				expire_desc = HAServer.callGetLocalFunc("ldapOperation", para).get('data')
			else:
				expire_desc = {}

			for users in netUser:
				tmp = users.split(':')
				
				name = tmp[0]
				uid = int(tmp[2])
				groups = []
				for group in tmp[3].split(','):
					groups.append(group)
				
				#get domain expiryDay and description
				if expire_desc.get(name.lower()):
					desc = expire_desc.get(name.lower()).get("description") if expire_desc.get(name.lower()).get("description") else ''
					expiryList = expire_desc.get(name.lower()).get("expires") if expire_desc.get(name.lower()).get("expires") else None
					if expiryList:
						if expiryList[0] != 0:
							expiry = str(expiryList[0])+'-'+str(expiryList[1])+'-'+str(expiryList[2])
							expirydate= datetime.date(int(expiryList[0]), int(expiryList[1]), int(expiryList[2]))
							isexpired = True if expirydate < datetime.date.today() else False
								
						else: 
							expiry = ''
							isexpired = False
					else: 
						expiry = ''
						isexpired = False
				else: 
					desc = (':').join(tmp[4:-2])
					expiry = ''
					isexpired = False
				
				#change userhome from /home/ImportedUser to link
				home = tmp[-2].replace("/home/ImportedUser",link)
				
				quota = quotaTable.get(str(uid))
				
				networkUsers.append({'type':'Network','name':name,'uid':uid,'groups':groups,'home':home,'desc':desc,'quota':quota, 'expiry':expiry, 'superuser':False, 'expiryDay':None, 'isexpired':isexpired,})
				
		except:
			HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
	### end of getting the network users ###
	
	return {'status':0,'data':networkUsers}

import re,urllib
def unescape(string):
	return urllib.unquote(re.sub(r'%u([a-fA-F0-9]{4}|[a-fA-F0-9]{2})', lambda m: unichr(int(m.group(1), 16)), string))

def getLocalUser(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff}
	
	### Get user quota ###
	retobjA = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getFileSystemData', 'controller':'A'}, logLevel = 2)
	if retobjA.get('status') != 0:
		HAServer.log(1, '>> [userOperation] error read => %s'%("quota A read error"))
		retobjA = {'data':[]}
	retobjB = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getFileSystemData', 'controller':'B'}, logLevel = 2)
	if retobjB.get('status') != 0:
		HAServer.log(1, '>> [userOperation] error read => %s'%("quota B read error"))
		retobjB = {'data':[]}
	
	quotaTable ={}
	fsList = retobjA['data'] + retobjB['data']
	for fsdata in fsList:
		fsname = fsdata['fsname']
		for quotaset in fsdata['quotas']:
			qtype = quotaset['type']		# may be 'user' or 'group'
			if qtype != 'user':
				continue
			for unit in quotaset['units']:
				id = unit['id']
				quota = str(long(unit['block-hard'])*1024)
				used = str(long(unit['block-used'])*1024)
				if quotaTable.has_key(id):
					quotaTable[id].append({'used':used, 'limit':quota, 'path':fsname})
				else:
					quotaTable.update({id:[{'used':used, 'limit':quota, 'path':fsname}]})
	
	f = open('/etc/group')
	group = f.read()
	f.close()
	member2group = {}
	superuserList = []
	for line in group.splitlines():
		if len(line.strip()) == 0:
			continue
		tmp = line.split(':')
		groupname = tmp[0]
		if groupname == 'root':
			superuserList = tmp[3].split(',')
			continue
		for member in tmp[3].split(','):
			if member2group.has_key(member):
				member2group[member].append(tmp[0])
			else:
				member2group[member] = [tmp[0]]
	
	
	f = open('/etc/shadow')
	shadow = f.read()
	f.close()
	name2expiry = {}
	for line in shadow.splitlines():
		if len(line.strip()) == 0:
			continue
		try:
			tmp = line.split(':')
			name = tmp[0]
			expiry = time.strftime('%Y-%m-%d',time.localtime((int(tmp[2])+int(tmp[4]))*86400))
			name2expiry[name] = expiry
		except:
			pass
	
	f = open('/etc/passwd')
	passwd = f.read()
	f.close()
	users = []
	homeList = []
	for line in passwd.splitlines():
		if len(line.strip()) == 0:
			continue
		try:
			tmp = line.split(':')
			name = tmp[0]
			uid = int(tmp[2])
			gid = int(tmp[3])
			desc = unescape(tmp[4]).encode('utf8')
			home = tmp[5]
			superuser = (name in superuserList)
			groups = ['users']
			if member2group.has_key(name):
				groups.extend(member2group[name])
			if not paraList.get('list_system'):
				if uid < 1000 or uid == 60002 or uid == 65534:
					continue
			homeList.append(home)
			quota = quotaTable.get(str(uid))
			expiry = name2expiry[name] if name2expiry.has_key(name) else ''
			users.append({'type':'Local','name':name,'uid':uid,'superuser':superuser,'groups':groups,'home':home,'desc':desc,'quota':quota,'expiry':expiry})
		except:
			pass
	
	paraListA = {
	'operation' : "checkFilesExist",
	'files' : homeList,
	'controller' : 'A',
	'serviceId' : paraList.get('serviceId') 
	}
	retA = HAServer.callGetLocalFunc("userOperation", paraListA,logLevel=3)
	
	paraListB = {
	'operation' : "checkFilesExist",
	'files' : homeList,
	'controller' : 'B',
	'serviceId' : paraList.get('serviceId') 
	}
	retB = HAServer.callGetLocalFunc("userOperation", paraListB,logLevel=3)
	
	for user in users:
		fileExist = retA['data'].get(user['home']) | retB['data'].get(user['home'])
		if not fileExist:
			user['home'] = '------'

	for user in users:
		user['quota'] = 'none'
	return {'status':0,'data':users}

def getAllUser(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff}
	data = []
	ret = getLocalUser(HAServer, paraList)
	data.extend(ret['data'])
	ret = getNetworkUser(HAServer, paraList)
	data.extend(ret['data'])
	
	return {'status':0,'data':data}

def exportUser(HAServer, paraList):
	ret = getAllUser(HAServer, paraList)
	userList = ret['data']
	
	csvFile = StringIO.StringIO()
	writer = csv.writer(csvFile)
	writer.writerow(['Name','Home Directory','Superuser','Type','Group','Quota','PWD Expiry Date','Description'])
	for user in userList:
		quota = user['quota'] if user.has_key('quota') else 'none'
		expiry = user['expiry'] if user.has_key('expiry') else ''
		writer.writerow([user['name'],user['home'], 'v' if user['superuser'] else '',user['type'],",".join(user['groups']),quota,expiry,user['desc']])
	
	name = 'UserList-%s.csv'%(time.strftime("%Y%m%d"),)
	
	if paraList.has_key('path'):
		path = '/%s/'%paraList['path'].strip('/')
		pathExist = False
		ret = HAServer.callGetLocalFunc("folderOperation", {'operation':'getAllFolders'},logLevel=3)
		if ret['status'] == 0:
			folderList = ret['data']
			for folder in folderList:
				if path.startswith('/%s/'%folder['path'].strip('/')):
					pathExist = True
		if not pathExist:
			return {'status':20,'msg':'path not exist'}
		
		ret = HAServer.callGetLocalFunc("userOperation", {'operation':'saveExportFile','name':name,'path':path,'file':csvFile.getvalue()})
		if ret['status'] == 20:
			ret = HAServer.callGetRemoteFunc("userOperation", {'operation':'saveExportFile','name':name,'path':path,'file':csvFile.getvalue()})
			return ret
		else:
			return ret
	else:
		return {'status':0,'data':{'name':name,'file':csvFile.getvalue()}}

def checkFilesExist(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		filesList = paraList.get('files')
		data = {}
		for file in filesList:
			data[file] = True
		return {'status':0,'data':data}
	
	filesList = paraList.get('files')
	data = {}
	for file in filesList:
		data[file] = os.path.exists(file)
	
	return {'status':0,'data':data}

def getAllUserByPagination(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff}
	
	try:
		### set default values ###
		pageSize = 1000		# number of maximum users
		beginIndex = 0		# starting index to query all users
		isOverEndIndex = False
		
		localUsers = []
		networkUsers = []
		allUsers = []
		
		
		### check the paraList ###
		if paraList.has_key('pageSize'):
			pageSize = paraList['pageSize']
			
		if paraList.has_key('beginIndex'):
			beginIndex = paraList['beginIndex']

			
		### Set the range ###
		endIndex = beginIndex + pageSize
		index = 0
		
		### Get user quota ###
		retobjA = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getFileSystemData', 'controller':'A'}, logLevel = 2)
		if retobjA.get('status') != 0:
			HAServer.log(1, '>> [userOperation] error read => %s'%("quota A read error"))
			retobjA = {'data':[]}
		retobjB = HAServer.callGetLocalFunc('folderOperation', {'operation': 'getFileSystemData', 'controller':'B'}, logLevel = 2)
		if retobjB.get('status') != 0:
			HAServer.log(1, '>> [userOperation] error read => %s'%("quota B read error"))
			retobjB = {'data':[]}
		
		quotaTable ={}
		fsList = retobjA['data'] + retobjB['data']
		for fsdata in fsList:
			fsname = fsdata['fsname']
			for quotaset in fsdata['quotas']:
				qtype = quotaset['type']		# may be 'user' or 'group'
				if qtype != 'user':
					continue
				for unit in quotaset['units']:
					id = unit['id']
					quota = str(long(unit['block-hard'])*1024)
					used = str(long(unit['block-used'])*1024)
					if quotaTable.has_key(id):
						quotaTable[id].append({'used':used, 'limit':quota, 'path':fsname})
					else:
						quotaTable.update({id:[{'used':used, 'limit':quota, 'path':fsname}]})
		if paraList.get('type') == 'local' or paraList.get('type') == 'all':
			### start getting the local users ###
			# 1. get all local users
			localUser = HAServer.getInfo("UserInfo", "getLocalInfo").get("data").get("users")
			homeList = []
			#for line in open('/etc/passwd','r'):
			for line in localUser:
				if len(line.strip()) == 0:
					continue
				try:
					tmp = line.split(':')
					
					uid = int(tmp[2])
					if not paraList.get('list_system'):
						if uid < 1000 or uid == 60002 or uid == 65534:
							continue
					
					if index >= endIndex:
						isOverEndIndex = True
						break
						
					if beginIndex <= index and index < endIndex:
						name = tmp[0]
						if paraList.get('userName'):
							if name != paraList.get('userName'):
								continue
						gid = int(tmp[3])
						desc = unescape(tmp[4]).encode('utf8')
						#desc = tmp[4]
						home = tmp[5].rstrip()
						superuser = False				# adjust
						groups = ['users']				# adjust
						
						homeList.append(home)
						expiry = ""						# adjust
						
						quota = quotaTable.get(str(uid))
						
						localUsers.append({'type':'Local','name':name,'uid':uid,'superuser':superuser,'groups':groups,'home':home,'desc':desc,'quota':quota, 'expiry':expiry, 'index':index, 'isEnd':False, 'expiryDay':None,'isexpired':None,})
						
					index = index +1
					
				except:
					HAServer.log(1, '>> [userOperation] error read => %s'%(str(line)))
					
			# if it contains local users
			if len(localUsers)>0:
				# 2 get super users array & user-to-group dict
				member2group = {}
				superuserList = []
				localgroup = HAServer.getInfo("UserInfo", "getLocalInfo").get("data").get("groups")
				#for line in open('/etc/group','r').read().splitlines():
				for line in localgroup:
					if len(line.strip()) == 0:
						continue
					tmp = line.split(':')
					groupname = tmp[0]
					if groupname == 'root':
						superuserList = tmp[3].split(',')
						continue
					for member in tmp[3].split(','):
						if member2group.has_key(member):
							member2group[member].append(tmp[0])
						else:
							member2group[member] = [tmp[0]]
			
				
				# 3. get user-to-expiryTime dict
				name2expiry = {}
				
				for line in open('/etc/shadow','r').read().splitlines():
					if len(line.strip()) == 0:
						continue
					try:
						tmp = line.split(':')
						name = tmp[0]
						if tmp[2] and tmp[4]:
							expiry = time.strftime('%Y-%m-%d',time.localtime((int(tmp[2])+int(tmp[4]))*86400))
							name2expiry[name] = (expiry, tmp[4])
					except:
						HAServer.log(1, '>> [userOperation] error read => %s'%(str(line)))
						
			
				# 4. update the information of users
				#ret = HAServer.callGetLocalFunc("checkFilesExist", {'files':homeList},logLevel=3)
				paraListA = {
				'operation' : "checkFilesExist",
				'files' : homeList,
				'controller' : 'A',
				'serviceId' : paraList.get('serviceId') 
				}
				retA = HAServer.callGetLocalFunc("userOperation", paraListA,logLevel=3)
				
				paraListB = {
				'operation' : "checkFilesExist",
				'files' : homeList,
				'controller' : 'B',
				'serviceId' : paraList.get('serviceId') 
				}
				retB = HAServer.callGetLocalFunc("userOperation", paraListB,logLevel=3)
				
				for user in localUsers:
					name = user['name']
					
					# update superuser information
					user['superuser']  = (name in superuserList)
					
					# update group information
					if member2group.has_key(name):
						user['groups'].extend(member2group[name])
					
					# update expiry information
					if name2expiry.has_key(name) :
						user['expiry'] = name2expiry[name][0]
						user['expiryDay'] = name2expiry[name][1]
						expirydate= datetime.date(int(user['expiry'].split('-')[0]), int(user['expiry'].split('-')[1]), int(user['expiry'].split('-')[2]))
						user['isexpired'] = True if expirydate < datetime.date.today() else False
					else:
						user['expiry'] = ''
						user['expiryDay'] = ''
						user['isexpired'] = False
					
					# update the home directory information
					fileExist = retA['data'].get(user['home']) | retB['data'].get(user['home'])
					if not fileExist:
						user['home'] = '------'
			else:
				pass
			### end of getting the local users ###
		updating = False
		if paraList.get('type') == 'domain' or paraList.get('type') == 'all':
			### start getting the network users ###
			# 1. Update ldap/ad Info
			ad_status,ldap_status, nis_status = False, False, False
			ret = HAServer.getInfo("ServiceInfo", "getServiceInfo", {"name":['AD', 'LDAP', 'NIS']} )
			if ret.get('status') == 0:
				ad_status = ret.get('data').get('AD').get('enabled')
				ldap_status = ret.get('data').get('LDAP').get('enabled')
				nis_status = ret.get('data').get('NIS').get('enabled')
			
			if ad_status or ldap_status or nis_status:
				updating = False
				Flag = HAServer.getInfo("UserInfo", "getUpdateFlag")
				if Flag.get('status') == 1:
					updating = True
				else:
					res = HAServer.setInfo("UserInfo", "updateNetworkInfo")
				netUser = []
				netUser = HAServer.getInfo("UserInfo", "getNetworkInfo").get("data").get("users")
			else:
				updating = False
				netUser = None
			
			# 2. If ldap/ad service or nis service is enable, load corresponding users
			if netUser:
				try:
					link = commands.getoutput('ls -al /home/ImportedUser').split()[-1]
					expire_desc = {}
					if ad_status or ldap_status :
						ret2 = HAServer.getInfo("UserInfo", "getNetworkExpired")
						if ret2.get('status') != 0:
							HAServer.log(1, '>> [userOperation] %s'%(str(ret2)))
						else:
							if ret2.get('data'):
								expire_desc = ret2.get('data')
					for users in netUser:
						tmp = users.split(':')
						
						name = tmp[0]
						if paraList.get('userName'):
							if name != paraList.get('userName'):
								continue
						uid = int(tmp[2])
						groups = []
						for group in tmp[3].split(','):
							groups.append(group)
						
						#get domain expiryDay and description
						if expire_desc.get(name.lower()):
							desc = expire_desc.get(name.lower()).get("description") if expire_desc.get(name.lower()).get("description") else ''
							expiryList = expire_desc.get(name.lower()).get("expires") if expire_desc.get(name.lower()).get("expires") else None
							if expiryList:
								if expiryList[0] != 0:
									expiry = str(expiryList[0])+'-'+str(expiryList[1])+'-'+str(expiryList[2])
									expirydate= datetime.date(int(expiryList[0]), int(expiryList[1]), int(expiryList[2]))
									isexpired = True if expirydate < datetime.date.today() else False
										
								else: 
									expiry = ''
									isexpired = False
							else: 
								expiry = ''
								isexpired = False
						else: 
							desc = (':').join(tmp[4:-2])
							expiry = ''
							isexpired = False
						
						#change userhome from /home/ImportedUser to link
						home = tmp[-2].replace("/home/ImportedUser",link)
						
						if index >= endIndex:
							isOverEndIndex = True
							break
						
						quota = quotaTable.get(str(uid))
						
						if index >= beginIndex and index < endIndex:
							networkUsers.append({'type':'Network','name':name,'uid':uid,'groups':groups,'home':home,'desc':desc,'quota':quota,'expiry':expiry, 'superuser':False, 'index':index, 'isEnd':False, 'expiryDay':None, 'isexpired':isexpired,})
						
						index = index +1
						
				except:
					HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
			### end of getting the network users ###
		
		
		### collect results and assign extended information ###
		if paraList.get('type') == 'local' or paraList.get('type') == 'all':
			allUsers.extend(localUsers)
		if paraList.get('type') == 'domain' or paraList.get('type') == 'all':
			allUsers.extend(networkUsers)
		
		if not isOverEndIndex:
			# it is the end of all user
			if len(allUsers)>0 :
				allUsers[-1]['isEnd'] = True
			return {'status':0, 'data':allUsers, 'isEnd':True, 'lastIndex': index, 'updating': updating}
			
		else:
			# get object after endIndex, so it is not the end of all group
			return {'status':0,'data':allUsers, 'isEnd':False, 'lastIndex': index, 'updating': updating}
		
	except KeyboardInterrupt:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
		
def saveExportFile(HAServer, paraList):
	name = paraList['name']
	path = paraList['path']
	file = paraList['file']
	if not os.path.isdir(path):
		return {'status':20,'msg':'path not exist'}
	try:
		f = open(os.path.join(path,name),'w')
		f.write(file)
		f.close()
	except:
		return {'status':10}
	
	return {'status':0}

def getNetworkGroup(HAServer, paraList):
	f = open('/etc/group')
	localGroup = f.read()
	f.close()
	
	ret,out,err = execute(['/usr/bin/getent','group'])
	out = out.replace(localGroup.strip(),'')
	data = []
	for line in out.splitlines():
		try:
			tmp = line.split(':')
			name = tmp[0]
			gid = int(tmp[2])
			members = tmp[3]
			groupDict = {'name':name,'gid':gid,'members':members,'type':'Network'}
			data.append(groupDict)
		except:
			pass
		
	return {'status':0,'data':data}
	
def getLocalGroup(HAServer, paraList):
	f = open('/etc/group')
	group = f.read()
	f.close()
	data = []
	for line in group.splitlines():
		if len(line.strip()) == 0:
			continue
		try:
			tmp = line.split(':')
			name = tmp[0]
			gid = int(tmp[2])
			members = tmp[3]
			if gid != 100 and (gid < 1000 or gid == 60001 or gid == 60002 or gid == 65534):
				continue
			groupDict = {'name':name,'gid':gid,'members':members,'type':'Local'}
			data.append(groupDict)
		except:
			pass
		
	return {'status':0,'data':data}
	
def getAllGroup(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff}
	data = []
	ret = getLocalGroup(HAServer, paraList)
	data.extend(ret['data'])
	ret = getNetworkGroup(HAServer, paraList)
	data.extend(ret['data'])
	
	return {'status':0,'data':data}

def exportGroup(HAServer, paraList):
	ret = getAllGroup(HAServer, paraList)
	groupList = ret['data']
	
	csvFile = StringIO.StringIO()
	writer = csv.writer(csvFile)
	writer.writerow(['Name','Type'])
	for group in groupList:
		writer.writerow([group['name'],group['type']])
	
	name = 'GroupList-%s.csv'%(time.strftime("%Y%m%d"),)
	
	if paraList.has_key('path'):
		path = '/%s/'%paraList['path'].strip('/')
		pathExist = False
		ret = HAServer.callGetLocalFunc("folderOperation", {'operation':'getAllFolders'},logLevel=3)
		if ret['status'] == 0:
			folderList = ret['data']
			for folder in folderList:
				if path.startswith('/%s/'%folder['path'].strip('/')):
					pathExist = True
		if not pathExist:
			return {'status':20,'msg':'path not exist'}
		
		ret = HAServer.callGetLocalFunc("userOperation", {'operation':'saveExportFile','name':name,'path':path,'file':csvFile.getvalue()})
		if ret['status'] == 20:
			ret = HAServer.callGetRemoteFunc("userOperation", {'operation':'saveExportFile','name':name,'path':path,'file':csvFile.getvalue()})
			return ret
		else:
			return ret
	else:
		return {'status':0,'data':{'name':name,'file':csvFile.getvalue()}}


def getAllGroupByPagination(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff}
	try:
		### set default values ###
		pageSize = 1000		# number of maximum users
		beginIndex = 0		# starting index to query all users
		isOverEndIndex = False
		
		localGroups = []
		networkGroups = []
		allGroups = []
		
		
		### check the paraList ###
		if paraList.has_key('pageSize'):
			pageSize = paraList['pageSize']
			
		if paraList.has_key('beginIndex'):
			beginIndex = paraList['beginIndex']
		
		
		### Set the range ###
		endIndex = beginIndex + pageSize
		index = 0

		if paraList.get('type') == 'local' or paraList.get('type') == 'all':
			### start getting the local groups ###
			
			# 1. get all local users
			f = open('/etc/group')
			group = f.read()
			f.close()
			
			# Get Group Description  
			GroupDescription = HAServer.getConfig("UserConfig", "getGroupDescription", paraList).get("data")
			
			for line in group.splitlines():
				if len(line.strip()) == 0:
					continue
				try:
					
					tmp = line.split(':')
					name = tmp[0]
					gid = int(tmp[2])
					
					if not paraList.get('list_system'):
						if gid != 100 and (gid < 1000 or gid == 60001 or gid == 60002 or gid == 65534):
							continue
						
					if index >= endIndex:
						isOverEndIndex = True
						break
						
					if beginIndex <= index and index < endIndex:		
						#HAServer.log(1, '>> [userOperation] %s ( %s , %s ) : %s'%(str(index), str(beginIndex), str(endIndex), str(line)))
						
						if GroupDescription.get(name):
							desc = unescape(GroupDescription.get(name)).encode('utf8')
						else:
							desc = ''
						groupDict = {'name':name, 'gid':gid, 'desc':desc, 'type':'Local', 'index':index, 'isEnd':False }
						localGroups.append(groupDict)
					
					index = index +1
					
				except:
					HAServer.log(1, '>> [userOperation] error pass => %s'%(str(line)))
	
			### end of getting the local groups ###			
		
		updating = False
		if paraList.get('type') == 'domain' or paraList.get('type') == 'all':
			### start getting the network groups ###
			# 1. Update ldap/ad Info
			ad_status,ldap_status, nis_status = False, False, False
			ret = HAServer.getInfo("ServiceInfo", "getServiceInfo", {"name":['AD', 'LDAP', 'NIS']} )
			if ret.get('status') == 0:
				ad_status = ret.get('data').get('AD').get('enabled')
				ldap_status = ret.get('data').get('LDAP').get('enabled')
				nis_status = ret.get('data').get('NIS').get('enabled')
			
			if ad_status or ldap_status or nis_status:
				updating = False
				Flag = HAServer.getInfo("UserInfo", "getUpdateFlag")
				if Flag.get('status') == 1:
					updating = True
				else:
					res = HAServer.setInfo("UserInfo", "updateNetworkInfo")
				netGroup = []
				netGroup = HAServer.getInfo("UserInfo", "getNetworkInfo").get("data").get("groups")
			else:
				updating = False
				netGroup = None
			
			# 2. If ldap/ad service or nis service is enable, load corresponding users
			if netGroup is not None:
				try:
					para = {'operation':'domainGroupInfo', 'controller': paraList.get('controller') }
					if ad_status or ldap_status :
						descList = HAServer.callGetLocalFunc("ldapOperation", para).get('data')
					else:
						descList = {}
					for groups in netGroup:
						tmp = groups.split(':')
						
						name = tmp[0]
						gid = int(tmp[2])
						
						if index >= endIndex:
							isOverEndIndex = True
							break
						
						if descList.get(name.lower()):
							desc = descList.get(name.lower()).get("description") if descList.get(name.lower()).get("description") else ''
						else:
							desc = ''
						
						if index >= beginIndex and index < endIndex:
							networkGroups.append({'name':name, 'gid':gid, 'type':'Network', 'desc':desc, 'index':index, 'isEnd':False})
						
						index = index +1
						
				except:
					HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
	
			### end of getting the network groups ###
		
		
		### collect results and assign extended information ###
		if paraList.get('type') == 'local' or paraList.get('type') == 'all':
			allGroups.extend(localGroups)
		if paraList.get('type') == 'domain' or paraList.get('type') == 'all':
			allGroups.extend(networkGroups)
		
		if not isOverEndIndex:
			# it is the end of all group
			if len(allGroups)>0 :
				allGroups[-1]['isEnd'] = True
			return {'status':0,'data':allGroups, 'isEnd':True, 'lastIndex': index, 'updating': updating}
		else:
			# get object after endIndex, so it is not the end of all group
			return {'status':0,'data':allGroups, 'isEnd':False, 'lastIndex': index, 'updating': updating}
			
			
	except KeyboardInterrupt:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}			

def getAllMembersByPagination(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xff}
	
	try:
		### set default values ###
		pageSize = 2000		# number of maximum users
		beginIndex = 0		# starting index to query all users
		isOverEndIndex = False

		allMembers = []
		
		
		### get updating flag
		ad_status,ldap_status, nis_status = False, False, False
		ret = HAServer.getInfo("ServiceInfo", "getServiceInfo", {"name":['AD', 'LDAP', 'NIS']} )
		if ret.get('status') == 0:
			ad_status = ret.get('data').get('AD').get('enabled')
			ldap_status = ret.get('data').get('LDAP').get('enabled')
			nis_status = ret.get('data').get('NIS').get('enabled')
		
		if ad_status or ldap_status or nis_status:
			updating = False
			Flag = HAServer.getInfo("UserInfo", "getUpdateFlag")
			if Flag.get('status') == 1:
				updating = True
			else:
				res = HAServer.setInfo("UserInfo", "updateNetworkInfo")
		else:
			updating = False
		
		### check the paraList ###
		if paraList.has_key('pageSize'):
			pageSize = paraList['pageSize']
			
		if paraList.has_key('beginIndex'):
			beginIndex = paraList['beginIndex']
		
		if paraList.has_key('beginIndex'):
			groupName = paraList['groupName']
		
		### Set the range ###
		endIndex = beginIndex + pageSize
		index = 0
		
		
		### get the member list ###
		grp_data = grp.getgrnam(groupName)
		pwd_data_list = pwd.getpwall()
		
		for pwd_data in pwd_data_list:
			if paraList.get('list_system'):
				if	(pwd_data.pw_uid <= 10000000) or (pwd_data.pw_uid > 10000000 and not pwd_data.pw_name.endswith('$')): 
					if pwd_data.pw_gid == grp_data.gr_gid:
						
						if index >= endIndex:
							isOverEndIndex = True
							break
						
						if beginIndex <= index and index < endIndex:		
							allMembers.append( {'name': pwd_data.pw_name.decode('utf8'), 'index': index, 'isEnd':False })
						
						index = index +1
			else:
				if (pwd_data.pw_uid >= 1000 and pwd_data.pw_uid <= 10000000) or (pwd_data.pw_uid > 10000000 and not pwd_data.pw_name.endswith('$')): 
					if pwd_data.pw_gid == grp_data.gr_gid:
						
						if index >= endIndex:
							isOverEndIndex = True
							break
						
						if beginIndex <= index and index < endIndex:		
							allMembers.append( {'name': pwd_data.pw_name.decode('utf8'), 'index': index, 'isEnd':False })
						
						index = index +1
		
		for mem in grp_data.gr_mem:
			if paraList.get('list_system'):
				if index >= endIndex:
					isOverEndIndex = True
					break			
					
				if beginIndex <= index and index < endIndex:
					allMembers.append({ 'name': mem.decode('utf8'), 'index': index, 'isEnd': False	})
				
				index = index +1
			else:
				if mem != 'root':
					if index >= endIndex:
						isOverEndIndex = True
						break			
						
					if beginIndex <= index and index < endIndex:
						allMembers.append({ 'name': mem.decode('utf8'), 'index': index, 'isEnd':False  })
					
					index = index +1
		
		### collect results and assign extended information ###
		if not isOverEndIndex:
			# it is the end of all group
			if len(allMembers)>0 :
				allMembers[-1]['isEnd'] = True
			return {'status':0,'data':allMembers, 'isEnd':True, 'lastIndex': index, 'updating': updating}
		else:
			# get object after endIndex, so it is not the end of all group
			return {'status':0,'data':allMembers, 'isEnd':False, 'lastIndex': index, 'updating': updating}
		
	except KeyboardInterrupt:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}	
		
		
def updateNetworkUserGroup(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0}
	try:
		#thismodule = sys.modules[__name__]
		#tmp = threading.Thread(target=getattr(thismodule, 'do_updateNetworkUserGroup'), args=(HAServer) )
		tmp = threading.Thread(target=do_updateNetworkUserGroup, args=(HAServer,) )
		tmp.setName('do_updateNetworkUserGroup')
		tmp.start()
		tmp2 = threading.Thread(target=do_updateNetworkExpired, args=(HAServer,{}) )
		tmp2.setName('do_updateNetworkExpired')
		tmp2.start()
		
		return {'status':0}
		
	except KeyboardInterrupt:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
def do_updateNetworkUserGroup(HAServer):
	try:
		ret = HAServer.setInfo("UserInfo", "refreshNetworkInfo")
		if ret.get('status') != 0:
			HAServer.log(1, '>> [userOperation] %s'%(str(ret)))
		return {'status':0}
		
	except KeyboardInterrupt:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
def do_updateNetworkExpired(HAServer, paraList):
	try:
		ad_status,ldap_status, nis_status = False, False, False
		ret1, ret2 = None, None
		ret = HAServer.getInfo("ServiceInfo", "getServiceInfo", {"name":['AD', 'LDAP', 'NIS']} )
		#check ad, ldap status
		if ret.get('status') == 0:
			ad_status = ret.get('data').get('AD').get('enabled')
			ldap_status = ret.get('data').get('LDAP').get('enabled')
		
		if ad_status or ldap_status :
			#kill process
			os.system("killall nmblookup")
			os.system("killall ldapsearch")
			
			#get expired
			para = {'operation':'domainAccountInfo', 'controller': HAServer.getCurrentController() }
			expire_desc = HAServer.callGetLocalFunc("ldapOperation", para).get('data')
			
			#set expired info
			ret1 = HAServer.setInfo("UserInfo", "setNetworkExpired", expire_desc)
			if ret1.get('status') != 0:
				HAServer.log(1, '>> [userOperation] %s'%(str(ret1)))
			
		return {'status':0}
		
	except KeyboardInterrupt:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1, 'data': traceback.format_exc()}
		
def getNetConnectionNumber(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xf}
	try:
		connection = {}
		#get FTP
		tmp = commands.getoutput('netstat -anp | grep ftp | grep tcp | grep -v 0.0.0.0 | grep -v :::')
		ftp_num = len(StringIO.StringIO(tmp).readlines())
		connection['ftp_num'] = ftp_num
		
		#get ssh 
		'''
		tmp = commands.getoutput('netstat -anp | grep ssh | grep tcp | grep -v 0.0.0.0 | grep -v ::: | grep @p')
		ssh_num = len(StringIO.StringIO(tmp).readlines())
		connection['ssh_num'] = ssh_num
		'''
		
		#get smb/cifs 
		tmp = commands.getoutput('netstat -anp | grep smb | grep tcp | grep -v 0.0.0.0 | grep -v :::')
		smb_num = len(StringIO.StringIO(tmp).readlines())
		connection['smb_num'] = smb_num
		
		#get nfs
		tmp = commands.getoutput('netstat -anp | grep 2049 | grep tcp | grep -v 0.0.0.0 | grep -v :::')
		iplist = []
		for lines in StringIO.StringIO(tmp).readlines():
			ip = lines.split()[4].split(':')[0]
			if ip not in iplist:
				iplist.append(ip)
		nfs_num = len(iplist)
		connection['nfs_num'] = nfs_num
		
		#get afp 
		tmp = commands.getoutput('netstat -anp | grep afp | grep tcp | grep -v 0.0.0.0 | grep -v ::: | grep -v tcp6')
		afp_num = len(StringIO.StringIO(tmp).readlines())
		connection['afp_num'] = afp_num
		
		connection['total'] = ftp_num + smb_num + nfs_num + afp_num
		
		return {'status':0 , 'connection':connection}
		
	except KeyboardInterrupt:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
def checkLocalNetworkUser(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xf}
	try:
		uid = paraList.get('uid')
		DictionaryUser = HAServer.getConfig("UserConfig", "getDictionaryUser", paraList).get("data")
		if DictionaryUser.has_key(uid):
			return {'status':0 , 'data':'Loacl'}
		else:
			return {'status':0 , 'data':'Network'}
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
	
def checkFolderisUserHome(HAServer, paraList):
	try:
		path = paraList.get('path')
		uid = os.stat(path).st_uid
		try:
			user = pwd.getpwuid(uid)
		except:
			return {'status':0 , 'name':''}
		
		if os.path.realpath(user.pw_dir) == os.path.realpath(path):
			return {'status':0 , 'name':user.pw_name}
		else:
			return {'status':0 , 'name':''}
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
		
def checkNetUserUpdating(HAServer, paraList):
	try:
		Flag = HAServer.getInfo("UserInfo", "getUpdateFlag")
		return Flag
		
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}
	
def userAuthenticate(HAServer, paraList):
	if HAServer.getCurrentController() != paraList.get('controller'):
		return {'status': 0xf}
	try:
		username = paraList.get('username')
		hashpasswd = paraList.get('password')
		password = base64.b64decode(hashpasswd)
		user_data = pwd.getpwnam(username)
		auth = ift_authenticate(username, password)
		if auth != 0:
			return {'status':0 , 'data':{'pass':False, 'uid':user_data.pw_uid}}
		else:
			return {'status':0 , 'data':{'pass':True, 'uid':user_data.pw_uid}}
	except:
		HAServer.log(1, '>> [userOperation] %s'%(str(traceback.format_exc())))
		return {'status':-1}

def check_user_home_collision(HAServer, paraList):
		name = paraList.get("name")
		home = paraList.get("home")
		isConflict = False
		try:
			if name and home:
				pwd_data_list = pwd.getpwall()
				for pwd_data in pwd_data_list:
					if pwd_data.pw_uid >= 1000 and pwd_data.pw_uid <= 10000000 and pwd_data.pw_shell == '/bin/nassh':
						if pwd_data.pw_dir.strip('/') == home.strip('/'):
							if pwd_data.pw_name != name:
								isConflict = True
								break
		except:
			isConflict = False
		finally:
			return {'status':0 , 'data':isConflict}
	
def userOperation(HAServer, paraList):
	try:
		operation = paraList.get('operation')
		opfunc = getattr(sys.modules[__name__],operation)
		return opfunc(HAServer, paraList)
	except:
		HAServer.log(0,traceback.format_exc())
		return {'status':100,'msg':'exception','traceback':traceback.format_exc(),'paraList':paraList}
