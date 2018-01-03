import os 
from ConfigTemplate import *
import xml.etree.ElementTree as ET
import xml
import copy
import sys
import traceback

class NTACLConfig(ConfigTemplate):

    def __init__ (self, serial):
        ConfigTemplate.__init__(self, serial)
        self.tree = ET.parse(self.getXMLPath('NTACLConfig'))
        self.root = self.tree.getroot()
    
    def config_test(self, paras):
        return {'status' : 0, 'data' : 'set config successfully'}

def main():
    x = NTACLConfig('1234')
    x.showConfig()
    
if __name__ == "__main__":
    try:
        func = getattr(sys.modules[__name__], sys.argv[1])
        func()
    except:
        print traceback.format_exc()
        main()
        
    
