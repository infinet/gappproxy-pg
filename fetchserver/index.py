#!/usr/bin/env python
# -*- coding: utf-8 -*-

# fetchserver/index.py
''' listen and send response back to client '''

import time
import logging
import wsgiref.handlers
from struct import unpack
from google.appengine.api import memcache
from google.appengine.api import urlfetch
#from google.appengine.api import urlfetch_errors
from google.appengine.runtime import DeadlineExceededError
from google.appengine.ext import webapp
from PycryptoWrap import Tiger

try:
    from urlparse import parse_qs  # urlparse.parse_qs only in Python 2.6
except ImportError:
    from cgi import parse_qs

HBH_HEADERS = frozenset(['proxy-authenticate', 'te', 'connection',
                         'keep-alive', 'proxy-connection', 'set-cookie',
                         'transfer-encoding', 'trailers', 'upgrade'])
FORBID_HEADERS = frozenset(['if-range', 'host'])
FETCH_MAX = 3
DEADLINE = 30


def dprint(msg, prefix='Debug: '):
    """print debug info on SDK console"""
    logging.info(prefix + msg)


def get_session_key(s_id):
    """Get the session_key from memcache, return None if not found
    Args:
        sess_id: the client's session id to look up
    Return:
        {session_id: key, hmac_id: hmac_key}"""
    key_block = memcache.get(s_id)
    if not key_block:
        keysoup = None
    else:
        expiretime = unpack('<i', key_block[-4:])[0]
        if time.time() > expiretime:
            return None
        keysoup = {'s_id': s_id,
               'srv_key': key_block[:Tiger.SKEY_SIZE],
               'srv_hmac': key_block[Tiger.SKEY_SIZE:
                                     Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE],
               'clt_key': key_block[Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE:
                                Tiger.SKEY_SIZE * 2 + Tiger.HMACKEY_SIZE],
               'clt_hmac': key_block[Tiger.SKEY_SIZE * 2 +
                                     Tiger.HMACKEY_SIZE: -4]}
    return keysoup


class MainHandler(webapp.RequestHandler, Tiger):
    # hop by hop header should not be forwarded

    def error_page(self, reqid, status, description):
        '''Generate the Error Page'''
        self.response.headers['Content-Type'] = 'application/octet-stream'
        content = []
        content.append('HTTP/1.1 %d %s' % (status, description))
        content.append('Content-Type: text/html')
        content.append('')
        content.append('<h1>Fetch Server Error</h1><p>Error Code:'
                       '%d</p><p>%s</p>' % (status, description))
        srv_resp = self.encrypt_aes(reqid + '\r\n'.join(content),
                                    aeskey=self.session_key,
                                    hmackey=self.session_hmac_key)
        self.response.out.write(srv_resp)

    def plain_error(self, status, msg=None):
        '''Generate the unencrypted Error Page'''
        self.response.headers['Content-Type'] = 'text/html; charset=UTF-8'
        self.response.set_status(status, msg)
        content = []
        content.append('<html><body>')
        content.append('<h2>%d %s</h2>' % (status, msg))
        content.append('</body></html>')
        self.response.out.write('\n'.join(content))

    def post(self):
        c_req = self.request.body

        # the session_id has been obfuscated by XOR
        obfus_key = c_req[:Tiger.SID_SIZE]
        session_id = self.xor_obfus(c_req[Tiger.SID_SIZE:Tiger.SID_SIZE * 2],
                                                                    obfus_key)
        res = get_session_key(session_id)
        if not res:
            # client will renegoatiate key upon receive 521 error
            self.plain_error(521, 'Internal Server Error')
            return

        self.session_key = res['srv_key']
        self.session_hmac_key = res['srv_hmac']

        p_req = self.decrypt_aes(c_req[Tiger.SID_SIZE * 2:],
                                 aeskey=res['clt_key'],
                                 hmackey=res['clt_hmac'])
        # prevent replay attack
        req_id = p_req[:Tiger.REQID_SIZE]
        p_req = p_req[Tiger.REQID_SIZE:]
        parse_request = parse_qs(p_req, keep_blank_values=True)
        # get original request
        orig_req = {}
        orig_req['method'] = parse_request['method'][0].upper()
        orig_req['path'] = parse_request['path'][0]
        orig_req['headers'] = parse_request['headers'][0]
        orig_req['payload'] = parse_request['payload'][0]

        # check method
        if orig_req['method'] not in set(['GET', 'HEAD', 'POST']):
            self.error_page(req_id, 590,
                            'Invalid local proxy, Method not allowed.')
            return

        ## check path, although client already checked
        #(scm, _, _, _, _, _) = urlparse.urlparse(orig_req['path'])
        #if scm.lower() not in ['http', 'https']:
        #    self.error_page(590,
        #                       'Invalid local proxy, Unsupported Scheme.')
        #    return
        # create new path
        new_path = orig_req['path']

        # create new headers
        new_headers = {}
        #content_length = 0
        for header in orig_req['headers'].rstrip().split('\r\n'):
            (name, _, value) = header.partition(':')
            name = name.strip()
            value = value.strip()
            if (name.lower() not in FORBID_HEADERS and
                        name.lower() not in HBH_HEADERS):
                new_headers[name] = value
            #if name.lower() == 'content-length':
            #    content_length = int(value)
        # add predfined header
        new_headers['Connection'] = 'close'

        # fetch, try * times
        resp = None
        for i in range(FETCH_MAX):
            try:
                # the last time, add Range to original header if it doesn't
                # have one
                if (i == FETCH_MAX - 1 and orig_req['method'] == 'GET'
                                    and ('Range' not in new_headers)):
                    new_headers['Range'] = 'bytes=0-65535'
                resp = urlfetch.fetch(new_path,
                                        payload=orig_req['payload'],
                                        method=orig_req['method'],
                                        headers=new_headers,
                                        deadline=DEADLINE,
                                        allow_truncated=False,
                                        follow_redirects=False,
                                        validate_certificate=True)
                ## success, no more try
                break
            except urlfetch.InvalidURLError, e:
                logging.error('Invalid URL: %s%s%s' % e,
                                          orig_req['method'], new_path)
            except urlfetch.ResponseTooLargeError, e:
                logging.error('Sorry, file size exceeds Google limit')
            except DeadlineExceededError:
                logging.error('DeadlineExceededError(deadline=%s, url=%r)',
                                DEADLINE, new_path)
                time.sleep(1)
            except urlfetch.DownloadError:
                logging.error('There was an error retrieving %s' % new_path)
                time.sleep(1)
            except Exception:
                if i == FETCH_MAX - 1:
                    return self.error_page(req_id, 591,
                            'The target server may be down or not exist.')
        # forward
        self.response.headers['Content-Type'] = 'application/octet-stream'
        # clear content
        content = []
        if resp:
            content.append('HTTP/1.1 %d %s' % (resp.status_code,
                       self.response.http_status_message(resp.status_code)))
            # headers
            for (resp_hd, resp_v) in resp.headers.iteritems():
                header = resp_hd.strip()
                if header.lower() not in HBH_HEADERS:
                    content.append('%s: %s' % (header, resp_v))

            # the response object of gapp urlfetch merge multiple headers with
            # same name together, separted by comma. When the header value
            # itself already contained comma, use header_msg.getheader to get a
            # list of values
            cookies = resp.header_msg.getheaders('Set-Cookie')
            if cookies:
                for cookie in cookies:
                    content.append('Set-Cookie: %s' % cookie)
            content.append('')
            content.append(resp.content)
            srv_resp = self.encrypt_aes(req_id + '\r\n'.join(content),
                                        aeskey=res['srv_key'],
                                        hmackey=res['srv_hmac'])
            self.response.out.write(srv_resp)
        else:
            self.error_page(req_id, 503,
                            'The target server may be down or not exist.')

    TEST_PAGE = '''<HTML><HEAD><TITLE>Test Page</TITLE></HEAD>
    <BODY> <H1>It Worked!</H1>
    If you can see this, then your installation was successful.
    <P></BODY></HTML>'''

    def get(self):
        self.response.headerlist = [('Content-type', 'text/html')]
        self.response.out.write(self.TEST_PAGE)
        return


def main():
    handler = MainHandler
    application = webapp.WSGIApplication([('/', handler)])
    wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
    main()
