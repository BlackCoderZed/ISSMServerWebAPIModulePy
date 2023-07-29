import os
import sys
from pathlib import Path


#########################################################################################
#                                  KeyInfo Class                                        #
#########################################################################################

class KeyInfo:
    def __init__(self, KeyName, Password):
        self.KeyName = KeyName
        self.Password = Password

#########################################################################################
#                                  Methods                                              #
#########################################################################################

########################
#      Operation       #
########################

def StartRegistrationProcess(keyName):
    GenerateKey(keyName)

def StartDeleteProcess(keyName):
    cmd = './easyrsa --batch revoke ' + keyName
    os.system(cmd)
    cmd2 = 'EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl'
    os.system(cmd2)
    cmd3 = 'rm -f /etc/openvpn/crl.pem'
    os.system(cmd3)
    cmd4 = 'cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem'
    os.system(cmd4)
    cmd5 = 'chmod 644 /etc/openvpn/crl.pem'
    os.system(cmd5)
    print('Deleted')
        

def GenerateKey(keyName):
    #Check Key is already exist
    existKey = CheckExist(keyName)
    if existKey == True:
        print('Already exist')
        return
    
    if keyInfo.Password == '':
        cmdStr = './easyrsa --batch build-client-full {} nopass'.format(keyInfo.KeyName)
        result = os.system(cmdStr)
        print('Key Register Process Result : '+str(result))

    #Determine Encryption Method
    TLS_SIG = GetEncryptionType()

    # Generates the custom client.ovpn
    homeDir = HOME_DIR
    cert_str = str(GetTemplate())
    
    cert_str += '<ca>\n'
    cert_str += str(GetCaInfo())
    cert_str += '</ca>\n'
    cert_str += '<cert>\n'
    cert_str += str(GetCertInfo(keyInfo.KeyName))
    cert_str += '</cert>\n'
    cert_str += '<key>\n'
    cert_str += str(GetKeyInfo(keyInfo.KeyName))
    cert_str += '</key>\n'

    if TLS_SIG == 1:
        cert_str += '<tls-crypt>\n'
        cert_str += str(GetTlsCrypt())
        cert_str += '</tls-crypt>\n'
    else :
        cert_str += '<tls-auth>\n'
        cert_str += str(GetTlsAuth())
        cert_str += '</tls-auth>\n'

    #create file
    fileName = homeDir + keyInfo.KeyName + '.ovpn'
    with open(fileName, 'w') as f:
        f.write(cert_str)


def CheckExist(keyName):
    with open('pki/index.txt','r') as f:
        logstr = f.read()
        if keyName in logstr:
            return True
        else:
            return False

def GetEncryptionType():
    with open('/etc/openvpn/server.conf', 'r') as f:
        logstr = f.read()
        if 'tls-crypt' in logstr:
            return 1
        else:
            return 2

def GetTemplate():
    with open('/etc/openvpn/client-template.txt','r') as f:
        return f.read()

def GetCaInfo():
    with open('/etc/openvpn/easy-rsa/pki/ca.crt','r') as f:
        return f.read()

def GetCertInfo(keyName):
    fileName = '/etc/openvpn/easy-rsa/pki/issued/'+keyName+'.crt'
    with open(fileName,'r') as f:
        lines = f.readlines()
        cert = ''
        startRead = False
        for line in lines:
            if 'BEGIN' in line:
                startRead = True
            if startRead == True:
                cert += line
            if 'END' in line:
                startRead = False
        return cert

def GetKeyInfo(keyName):
    filename = '/etc/openvpn/easy-rsa/pki/private/'+keyName+'.key'
    with open(filename,'r') as f:
        return f.read()

def GetTlsCrypt():
    with open('/etc/openvpn/tls-crypt.key','r') as f:
        return f.read()

def GetTlsAuth():
    with open('/etc/openvpn/tls-auth.key','r') as f:
        return f.read()

#########################################################################################
#                                  Entry Point                                          #
#########################################################################################
CMD_CODE = sys.argv[1]
KEY_NAME = sys.argv[2]
HOME_DIR = sys.argv[3]
print(CMD_CODE)
print(KEY_NAME)
print(HOME_DIR)
if CMD_CODE == 1:
	StartRegistrationProcess(KEY_NAME)
else :
	StartDeleteProcess(KEY_NAME)

