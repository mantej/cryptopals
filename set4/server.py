import web
from time import sleep
import hmac
from hashlib import sha1

urls = ("/.*", "server")
app = web.application(urls, globals())

class server:
    def GET(self):
        user_data = web.input()
        f = user_data.file
        s = user_data.signature
        code = verifyHMAC(f, s)
        if code:
            return web.HTTPError("200")
        return web.HTTPError("500")

def insecure_compare(str1, str2):
    if len(str1) != len(str2):
        return False
    for i in range(len(str1)):
        if str1[i] != str2[i]:
            return False
        sleep(0.005) # change to 0.05 for 4-31
    return True

def verifyHMAC(file, sig):
    key = 'YELLOWSUBMARINE'
    h = hmac.new(key,'',sha1)
    h.update(file)
    hmac_digest = h.hexdigest()
    return insecure_compare(hmac_digest, sig)


if __name__ == "__main__":
    app.run()
