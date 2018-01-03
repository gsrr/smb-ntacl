from samba.samba3 import smbd, passdb
from samba.samba3 import param as s3param
from samba.dcerpc import security
s3conf = s3param.get_context()
s3conf.load("/etc/samba/smb.conf")
#pdb = passdb.PDB(s3conf.get("passdb backend"))
pdb = passdb.PDB('tdbsam')
print dir(pdb)
print pdb.uid_to_sid(100001)
dsid = security.dom_sid("S-1-5-21-2896997548-2896997548-2896997548-100001")
print pdb.sid_to_id(dsid)
gsid = security.dom_sid("S-1-5-21-2896997548-2896997548-2896997548-50001")
print pdb.sid_to_id(gsid)
