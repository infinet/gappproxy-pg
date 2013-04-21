#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''Generate or re-generate RSA keypairs for client and server'''

import os
import shutil
from PycryptoWrap import Tiger


scriptpath = os.path.split(os.path.realpath( __file__ ))[0]
scriptpath = os.path.split(scriptpath)[0]
ID_RSA = os.path.join(scriptpath,'local', 'id_rsa')
ID_RSA_PUB = os.path.join(scriptpath, 'local', 'id_rsa.pub')
AUTH__KEY_SRV = os.path.join(scriptpath, 'local', 'hq.pub')

ID_RSA_SRV = os.path.join(scriptpath,'fetchserver', 'id_rsa')
ID_RSA_PUB_SRV = os.path.join(scriptpath, 'fetchserver', 'id_rsa.pub')
AUTH__KEY = os.path.join(scriptpath, 'fetchserver', 'user1.pub')

def main():
    tiger = Tiger()
    print '\nGenerating client pub/private keypair...'
    tiger.gen_rsa_keypair(ID_RSA_PUB, ID_RSA)

    print '\nGenerating server pub/private keypair...'
    tiger.gen_rsa_keypair(ID_RSA_PUB_SRV, ID_RSA_SRV)

    print '\nCopy Client Public key to fetch server directory'
    shutil.copy(ID_RSA_PUB, AUTH__KEY)

    print 'Copy server Public key to client directory'
    shutil.copy(ID_RSA_PUB_SRV, AUTH__KEY_SRV)


if __name__ == "__main__":
    main()

