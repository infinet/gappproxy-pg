#! /usr/bin/env python
# -*- coding: utf-8 -*-

# local/proxy.py
''' A modified GAppProxy use Pycrypto RSA and AES to encrypt connection '''


from Crypto import Random
from PycryptoWrap import Tiger
from PycryptoWrap import PRF
from StringIO import StringIO
import BaseHTTPServer
import SocketServer
import os
import platform
from struct import pack
import re
import hashlib
import sys
import time
import urllib
import urllib2
import urlparse


if platform.system() == 'Windows':
    info = '在浏览器里设置http代理为localhost，端口8000\n可以翻墙了'
    info = info.decode('utf-8').encode(sys.getfilesystemencoding())

    def dprint(msg):
        """print colorfule debug message"""
        print 'debug: ' + str(msg)
else:
    info = 'Start serving...'
    import console

    def dprint(msg):
        """print colorfule debug message"""
        print console.colorize('red', 'debug: ' + str(msg))


MAX_TRUNK = 1024 * 256  # max 256K in range fetch
RE_RANGE = re.compile(r'bytes[ \t]+([0-9]+)-([0-9]+)/([0-9]+)')
REMOVE_GAPP = frozenset(['content-length', 'accept-ranges', 'content-range'])
RESUME_EXT = frozenset(['mp3', 'mp4', 'avi', 'flv', 'msi', 'exe',
                        'deb', 'lzma', 'zip', 'gz', 'tgz', 'bz2', 'xz'])
NON_RANGE_HTTPCODE = frozenset([200, 301, 302, 303, 307, 404, 416, 503])
SP_ERROR = {404: 'Local proxy error, Fetchserver not found',
            502: 'Local proxy error, network error or fetchserver too busy',
            521: 'Session key not found, perhaps expired? re-login now',
            522: 'Just acquired a new encryption key, retrying ...',
            523: 'Re-negotiating encryption key, please wait ...',
            524: 'Another key negotiation is running, wait 3 seconds ...'}

def get_config():
    '''parse the configure file, return a dictionary of preconfigured
    shapes and locations'''
    import ConfigParser
    conf_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    conf_file = os.path.join(conf_dir, 'proxy.conf')
    config = ConfigParser.ConfigParser()
    config.read(conf_file)

    confs = {'listen_port': 8000,
             'fetch_server':'localhost',
             'local_proxy':'',
             'self': {}}
    gae_keys = ('listen_address', 'fetch_server', 'fetch_path',
                'login_path', 'proxy_choice', 'ipv6_proxy')

    for key in gae_keys:
        try:
            confs[key] = config.get('gae', key)
        except ConfigParser.NoOptionError:
            pass

    try:
        pchoice = config.get('proxies', confs['proxy_choice'])
        confs['local_proxy'] = fmt_proxy(pchoice)
    except ConfigParser.NoOptionError:
        confs['local_proxy'] = None

    try:
        confs['ipv6_proxy'] = fmt_proxy(
                                config.get('proxies', confs['ipv6_proxy']))
    except ConfigParser.NoOptionError:
        confs['ipv6_proxy'] = None

    confs['name'] = config.get('self', 'name')
    confs['priv'] = os.path.join(conf_dir, config.get('self', 'priv'))
    confs['pub'] = os.path.join(conf_dir, config.get('gae', 'pub'))

    return confs


def read_header(httpmsg, statusonly=False):
    """parse header from raw http message
    Args:
        httpmsg: the raw http message
    return: a dict {'User-Agent': xx, 'Content-Length', xx}
            only interested in content-range, http status code"""

    res = {'Header': [], 'Body': None,
           'cur_start': None, 'cur_end': None, 'total_len': None}
    resp = StringIO(httpmsg)
    http_status = resp.readline().split()
    res['Status_code'] = int(http_status[1])
    res['Status_name'] = ' '.join(http_status[2:])
    if statusonly:
        return res
    while True:
        line = resp.readline().strip()
        if line == '':  # end header
            break
        (name, _, value) = line.partition(':')
        name = name.strip()
        value = value.strip()
        res['Header'].append([name, value])

        if name.lower() == 'content-range':
            try:
                m_rng = RE_RANGE.match(value)
                res['cur_start'] = int(m_rng.group(1))
                res['cur_end'] = int(m_rng.group(2))
                res['total_len'] = int(m_rng.group(3))
            except AttributeError:
                print 'Content-Range header Error, HTTP {0}: {1}'.format(
                            res['Status_code'], res['Status_name'])
    res['Body'] = resp.read()
    #debug_logf.write('\n\n' + str(res['Header']))
    #debug_logf.write(res['Body'])
    return res


def pretty_byte(num):
    '''pretty format bytes into bytes, KiB, or MiB'''
    if num > 1000000:
        res = '%.2f MiB' % (num / 1000000.0)
    elif num > 1000:
        res = '%.2f KiB' % (num / 1000.0)
    else:
        res = '%d Bytes' % num
    return res


def pretty_num(num):
    '''add thousand seperator'''
    numstr = str(num)
    res = []
    while len(numstr) >= 3:
        res.append(numstr[-3:])
        numstr = numstr[:-3]
    if numstr:
        res.append(numstr)
    res.reverse()
    return ','.join(res)


def open_request(path, data, proxy=None):
    '''request handle
    Args:
        path: the request URL
        data: POST method payload
        proxies: a dict in form of {'http': xx, 'https': yy}
    Return:
        an opener'''
    request = urllib2.Request(path)
    request.add_data(data)
    request.add_header('Content-Type', 'application/octet-stream')
    request.add_header('User-Agent',
                       'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
    if not proxy:
        proxy = {}
    opener = urllib2.build_opener(urllib2.ProxyHandler(proxy))
    urllib2.install_opener(opener)
    # The HTTP request will be a POST instead of a GET when the data
    # parameter is provided, http://docs.python.org/library/urllib2
    return urllib2.urlopen(request)


class HandlerStatistic(BaseHTTPServer.BaseHTTPRequestHandler):
    '''use this class to retain stateful information'''
    stat = {'sendcnt': 0, 'getcnt': 0, 'rcvbytes': 0}


class LocalProxyHandler(HandlerStatistic, Tiger):
    '''the main part'''

    lock = False
    unlock_time = 0

    def relogin(self):
        ''' Re-Negotiate the session keys
        the relogin may be called when a new key is negotiating, or just after
        a new key acquired(several thread try to connect gapp at the same time,
        some thread received 521 error which trigger relogin first, some thread
        was somehow delayed and when they received 521 error and try to get a
        new key, that new key has JUST ACQUIRED
        '''

        if LocalProxyHandler.lock:
            # 524: 'Another key negotiation thread is running ...'
            print SP_ERROR[524]
            time.sleep(3)
            self.retry_do_method()
            return
        # just acquired a new key. time since last new key
        if time.time() - LocalProxyHandler.unlock_time < 10:
            # 522: 'Just acquired a new encryption key, retrying ...'
            print SP_ERROR[522]
            self.retry_do_method()
            return

        # 523: 'Re-negotiating encryption key, please wait ...'
        print SP_ERROR[523]

        LocalProxyHandler.lock = True
        clt_conn = ClientHello(cfg=self.cfg)
        LocalProxyHandler.keysoup = clt_conn.onestep_login()

        if clt_conn.login_okay:
            LocalProxyHandler.lock = False
            LocalProxyHandler.unlock_time = time.time()
            print '\nNew encryption keys acquired\n'
            logfp = open('/tmp/GappProxyPG.log', 'a')
            ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            keyhash = hashlib.md5(
                            LocalProxyHandler.keysoup['clt_key']).hexdigest()
            logfp.write('[%s] new key acquired: %s\n' % (ctime, keyhash))
            logfp.close()
            self.retry_do_method()

    def retry_do_method(self):
        self.keysoup = LocalProxyHandler.keysoup
        self.do_method()

    def custom_gapp_error(self, errcode):
        """A convenient wrap of self.send_error"""
        if errcode in SP_ERROR:
            self.send_error(errcode, SP_ERROR[errcode])
        else:
            self.send_error(errcode)

    def do_connect(self):
        """The https proxy, it will send an error message to client"""

        self.send_error(501, 'https proxy not supported')
        self.connection.close()

    def do_method(self):
        '''The http proxy handle'''

        if LocalProxyHandler.lock:
            print SP_ERROR[524]
            time.sleep(3)
            self.retry_do_method()
            return

        self.fetch_srv = norm_address(self.cfg['fetch_server'] +
                                      self.cfg['fetch_path'])
        self.login_srv = norm_address(self.cfg['fetch_server'] +
                                      self.cfg['login_path'])
        self.proxy = self.cfg['local_proxy']

        (scheme, netloc, path, _, _, _) = urlparse.urlparse(self.path)
        if scheme.lower() not in ['http', 'https'] or not netloc:
            self.send_error(501,
                    'Local proxy error, %s is not supported' % scheme)
        else:
            method = self.command
            if method not in set(['GET', 'HEAD', 'POST', 'PUT', 'DELETE']):
                self.send_error(501,
            'Local proxy error, only GET/HEAD/POST/PUT/DELETE method allowed.')

            elif method == 'GET' and 'Range' in self.headers:
                self._range_fetch()
            else:
                if path.split('.')[-1].lower() in RESUME_EXT:
                #if path[-4:].lower() in RESUME_EXT:
                    self._range_fetch()
                else:
                    self._normal_fetch()
        self.connection.close()

    def _normal_fetch(self):
        """
        assume requested file is regular sized, if GAPP return code 206, then
        switch to process_large_response"""

        HandlerStatistic.stat['sendcnt'] += 1
        print '  Send[{0}]: {1} {2}'.format(self.stat['sendcnt'],
                                            self.command, self.path)

        payload = ''
        if self.command in ('POST', 'PUT'):
            # get 'Content-Length' from headers, 0 if no match
            payload_len = int(self.headers.get('Content-Length', 0))
            if payload_len > 0:
                payload = self.rfile.read(payload_len)

        # create a plain request
        plain_params = urllib.urlencode({'method': self.command,
                                         'path': self.path,
                                         'headers': self.headers,
                                         'payload': payload})

        req_id = Random.get_random_bytes(self.REQID_SIZE)

        # A fixed session_id is too obvious, so use a random string XOR with it
        # to make it hard to see pattern
        obfus_key = Random.get_random_bytes(self.SID_SIZE)
        obfus_key += self.xor_obfus(self.keysoup['s_id'], obfus_key)
        plain_params = req_id + plain_params
        msg = obfus_key + self.encrypt_aes(plain_params,
                                           aeskey=self.keysoup['clt_key'],
                                           hmackey=self.keysoup['clt_hmac'])


        # encrypt, send plain request to gapp, and get response
        try:
            resp_encrypted = open_request(self.fetch_srv,
                                              msg, self.proxy).read()
            HandlerStatistic.stat['getcnt'] += 1
            HandlerStatistic.stat['rcvbytes'] += len(resp_encrypted)
        except urllib2.HTTPError, err:
            if err.code == 521:
                self.relogin()
            else:
                self.custom_gapp_error(err.code)
            return
        except urllib2.URLError, err:
           dprint('i am in URLError')
           dprint(err)
           return

        resp_decrypted = self.decrypt_aes(resp_encrypted,
                                          aeskey=self.keysoup['srv_key'],
                                          hmackey=self.keysoup['srv_hmac'])

        if resp_decrypted[:16] != req_id:
            dprint(resp_encrypted)
            raise HandshakeError('Possible Replay Attack while'
                                     ' fetching {0}'.format(self.path))
            return
        resp_decrypted = resp_decrypted[16:]
        soup = read_header(resp_decrypted, statusonly=True)

        # if large response
        if soup['Status_code'] == 206 and self.command == 'GET':
            self._range_fetch()
        else:
            print '%s[%s]: %s [%s %s] %s' % (self.command,
                                           HandlerStatistic.stat['getcnt'],
                                           self.path,
                                           soup['Status_code'],
                                           soup['Status_name'],
                             pretty_byte(HandlerStatistic.stat['rcvbytes']))
            self.wfile.write(resp_decrypted)

    def dl_progress(self, curpos, totalsize):
        percent = int(curpos * 100.0 / totalsize)
        return '%2d%% of %s' % (percent, pretty_byte(totalsize))

    def _range_fetch(self):
        """GAPP Limit: request 5M, response 32M"""
        # find the client's range request, if any, to support resume example:
        # "Range: bytes=0-1048575"
        HandlerStatistic.stat['sendcnt'] += 1
        print '  Send[{0}] Range Request: {1} {2}'.format(self.stat['sendcnt'],
                                                     self.command, self.path)
        try:
            cur_pos = int(self.headers['Range'].split('=')[1].split('-')[0])
            print '  Resuming {0} from {1}'.format(self.path, cur_pos)
        except KeyError:
            cur_pos = 0

        part_len = MAX_TRUNK
        first_part = True
        part_count = 1
        allowed_failed = 10

        while allowed_failed > 0:
            self.headers['Range'] = 'bytes=%d-%d' % (cur_pos,
                                                     cur_pos + part_len - 1)
            # create request for GAppProxy
            plain_params = urllib.urlencode({'method': 'GET',
                                             'path': self.path,
                                             'headers': self.headers,
                                             'payload': ''})
            req_id = Random.get_random_bytes(self.REQID_SIZE)
            plain_params = req_id + plain_params
            obfus_key = Random.get_random_bytes(self.SID_SIZE)
            obfus_key += self.xor_obfus(self.keysoup['s_id'], obfus_key)
            msg = obfus_key + self.encrypt_aes(plain_params,
                                           aeskey=self.keysoup['clt_key'],
                                           hmackey=self.keysoup['clt_hmac'])

            try:
                resp_encrypted = open_request(self.fetch_srv,
                                              msg, self.proxy).read()
                HandlerStatistic.stat['getcnt'] += 1
                HandlerStatistic.stat['rcvbytes'] += len(resp_encrypted)
            except urllib2.HTTPError, err:
                if err.code == 521:  # session key expired
                    self.relogin()
                else:
                    self.custom_gapp_error(err.code)
                allowed_failed = 0
            except urllib2.URLError, err:
                allowed_failed = 0

            resp_decrypted = self.decrypt_aes(resp_encrypted,
                                          aeskey=self.keysoup['srv_key'],
                                          hmackey=self.keysoup['srv_hmac'])

            if resp_decrypted[:16] != req_id:
                raise HandshakeError('replay attack')
                return
            resp_decrypted = resp_decrypted[16:]
            soup = read_header(resp_decrypted)

            if soup['Status_code'] == 206:
                if first_part:
                    # modfied the header send back to client
                    self.send_response(200, 'OK')
                    for header in soup['Header']:
                        if header[0].lower() not in REMOVE_GAPP:
                            self.send_header(header[0], header[1])
                    if soup['total_len']:
                        self.send_header('Content-Length',
                                     soup['total_len'] - soup['cur_start'])
                        #self.send_header('Accept-Ranges', 'none')
                        self.send_header('Content-Range',
                                 'bytes {0}-{1}/{2}'.format(soup['cur_start'],
                                                    soup['total_len'] - 1,
                                                    soup['total_len']))
                        self.end_headers()
                        first_part = False
                res = soup['Body']
                part_count += 1
                next_pos = soup['cur_end'] + 1
                # next part?
                if next_pos == soup['total_len']:
                    allowed_failed = 0
                cur_pos = next_pos
                print 'Get {0} {1}'.format(self.path,
                                self.dl_progress(next_pos, soup['total_len']))
            elif soup['Status_code'] in NON_RANGE_HTTPCODE:
                print '%s %s %s %s' % (self.command, self.path,
                                   soup['Status_code'], soup['Status_name'])
                res = resp_decrypted
                allowed_failed = 0
            else:  # != 206
                # reduce part_len and try again
                if part_len > 65536:
                    part_len /= 2
                allowed_failed -= 1

            HandlerStatistic.stat['getcnt'] += 1
            print '%s[%s]: %s [%s %s] %s' % (self.command,
                                 HandlerStatistic.stat['getcnt'], self.path,
                                             soup['Status_code'],
                                             soup['Status_name'],
                               pretty_byte(HandlerStatistic.stat['rcvbytes']))
            self.wfile.write(res)

    do_GET = do_method
    do_HEAD = do_method
    do_POST = do_method
    do_PUT = do_method


class ThreadingHTTPServer(SocketServer.ThreadingMixIn,
                          BaseHTTPServer.HTTPServer):
    '''the proxy server itself'''
    pass


def fmt_proxy(proxy):
    '''return a dict'''
    if len(proxy.split(':')) == 1:
        proxy += ':80'
    return {'http': proxy, 'https': proxy}


class HandshakeError(Exception):
    """ self defined error class"""
    pass


class ClientHello(Tiger):
    """client initiate hello"""

    def __init__(self, cfg=None):
        # Generate a 256 byte long string for the session: 32 bytes for
        # identify the session, 16 bytes(128 bits) for AES, 32 bytes(256 bits)
        # for HMAC, the rest of string serve to complicate the cipher text,
        # avoid padding

        self.fetch_srv = norm_address(cfg['fetch_server'] + cfg['fetch_path'])
        self.login_srv = norm_address(cfg['fetch_server'] + cfg['login_path'])
        self.proxy = cfg['local_proxy']

        self.username = cfg['name']
        #self.key_soup = Random.get_random_bytes(Tiger.RSAOBJ_SIZE - 42)
                #self.session_id = Random.get_random_bytes(Tiger.SID_SIZE)
        #self.session_key = self.key_soup[:Tiger.SKEY_SIZE]
        #self.session_hmac_key = self.key_soup[
        #                Tiger.SKEY_SIZE:Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE]
        self.rsa_hqpub = self.import_key(open(cfg['pub']))
        self.rsa_priv = self.import_key(open(cfg['priv']))
        self.sign_hqpub = self.import_sign_key(open(cfg['pub']))
        self.sign_priv = self.import_sign_key(open(cfg['priv']))
        self.login_okay = False

    def onestep_login(self):
        """Send client pubkey with aes key to server in one step, the message
        formatted as:
        """
        try:
            server_finish = open_request(self.login_srv, self.onestep()).read()
        except HandshakeError:
            return None


        #dprint('server finish message\nhash=%s\nsize=%d' %
        #   (hashlib.md5(server_finish).hexdigest(), len(server_finish)))

        payload = self.rsa_priv.decrypt(server_finish[:Tiger.RSAOBJ_SIZE])
        srv_rsa_sign = server_finish[Tiger.RSAOBJ_SIZE:]
        if not self.verify(self.sign_hqpub, payload, srv_rsa_sign):
            print 'Signature of Server Finish Message is wrong'
            return None
        srv_random = payload[:32]
        s_id = payload[32: 32 + Tiger.SID_SIZE]
        srv_verify_data = payload[32 + Tiger.SID_SIZE:]


        master_secret = PRF(self.pre_master_secret, 'master secret',
                            self.client_random + srv_random, 48)

        hshk = s_id + self.client_random + srv_random + self.pre_master_secret
        hshk_hash = hashlib.sha256(hshk).digest()
        verify_data = PRF(master_secret, 'server finished',
                          hshk_hash, 32)

        if srv_verify_data != verify_data:
            print 'The hash value of all randoms is not match'
            return None
        # at last, the key bl
        key_block_size = (Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE) * 2
        key_block = PRF(master_secret, 'key expansion',
                        self.client_random + srv_random, key_block_size)

        keysoup = {'s_id': s_id,
                   'srv_key': key_block[:Tiger.SKEY_SIZE],
                   'srv_hmac': key_block[Tiger.SKEY_SIZE:
                                         Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE],
                   'clt_key': key_block[Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE:
                                    Tiger.SKEY_SIZE * 2 + Tiger.HMACKEY_SIZE],
                   'clt_hmac': key_block[Tiger.SKEY_SIZE * 2 +
                                         Tiger.HMACKEY_SIZE:]}
        self.login_okay = True
        return keysoup

    def onestep(self):
        """load remote pubkey from local file, use RSA to encrypt the aes key
        , then send to server"""
        ctime = time.strftime('%H:%M:%S', time.localtime())
        print ('[{0}] Login into server.....'.format(ctime))

        self.pre_master_secret = Random.get_random_bytes(48)
        self.client_random = (pack('<i', time.time()) +
                                          Random.get_random_bytes(28))
        msg = ('{0:20}'.format(self.username) + self.pre_master_secret +
                               self.client_random)

        rsa_e = self.rsa_hqpub.encrypt(msg)
        rsa_sign = self.sign(self.sign_priv, msg)
        return rsa_e + rsa_sign


def norm_address(url):
    """ensure the url is in correct form"""
    url = url.lower()
    if url.startswith('http'):
        return url
    else:
        return 'http://' + url


def main():
    runtime_cfg = get_config()
    clt_conn = ClientHello(cfg=runtime_cfg)
    listen_port = int(runtime_cfg['listen_address'].split(':')[1])
    #try:
    keysoup = clt_conn.onestep_login()
    #except urllib2.URLError:
    #    if http_proxy:
    #        print '%s appears been blocked' % http_proxy['http']
    #    http_proxy = runtime_cfg['ipv6_proxy']
    #    clt_conn = ClientHello(login_srv, f_srv, http_proxy)
    #    clt_conn.onestep_login()

    print '***********GappProxy Privacy Guard**********'
    print ''
    print '--------------------------------------------'
    print 'Logging into %s' % runtime_cfg['fetch_server']
    if not clt_conn.login_okay:
        print 'Authentication failed.'
    else:
        print 'Authentication successful.'
        print ''
        print '--------------------------------------------'
        #print 'HTTPS Enabled: %s' % (ssl_enabled and 'YES' or 'NO')
        print 'HTTPS Disabled'
        print 'Listen Addr  : 127.0.0.1:%d' % listen_port
        if clt_conn.proxy:
            print 'Local Proxy  : %s' % clt_conn.proxy['http']
        print 'Fetch Server : %s' % runtime_cfg['fetch_server']
        print '--------------------------------------------'
        print ''
        print info
        LocalProxyHandler.keysoup = keysoup
        handler = LocalProxyHandler
        handler.cfg = runtime_cfg

        httpd = ThreadingHTTPServer(('127.0.0.1', listen_port), handler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.shutdown()


if __name__ == '__main__':
    main()
