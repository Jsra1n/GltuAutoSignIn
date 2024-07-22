# coding = utf-8
from urllib.request import urlretrieve
from Crypto.Cipher import AES
import requests
import base64
import json
import os
import re





# 加解密
class Crypto(object):
    def __init__(self):
        # pubkey值
        self.key = 'SERVICEABCDE_key'.encode('utf-8')
        # 偏移量
        self.iv = b'SERVICEABCDEF_iv'
        # AES-CBC对称加密
        self.mode = AES.MODE_CBC
        # AES-CBC-PKCS5格式化字符串
        self.bs = 16
        self.PADDING = lambda s: s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
 
    # AES-CBC加密
    def AESEncrypt(self, text):
        generator = AES.new(self.key, self.mode, self.iv)
        crypt = generator.encrypt(self.PADDING(text).encode("utf-8"))
        # 加密后转base64
        crypted_str = base64.b64encode(crypt)
        result = crypted_str.decode()
        return result



#登录获取token
def get_token():
    user = "202036610235"
    pwd = "Gltu142519"
    host = "https://server.gltu.cn/"
    endpoint=r"/servicehall/backend/web/loginCopy"
    url = ''.join([host,endpoint])
    headers = \
        {
            "Host": "server.gltu.cn",
            "Connection": "keep-alive",
            "Content-Length": "111",
            "Accept": "application/json, text/plain, */*",
            "X-XSS-Protection": "1",
            "X-Content-Type-Options": "nosniff",
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 11; zh-cn; Mi 10 Pro Build/RKQ1.200826.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36 XiaoMi/MiuiBrowser/15.9.16 swan-mibrowser",
            "isMobile": "1",
            "Content-Type": "application/x-www-form-urlencoded; charset\u003dUTF-8",
            "Origin": "https://server.gltu.cn",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://server.gltu.cn/wap/login",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q\u003d0.9,en-US;q\u003d0.8,en;q\u003d0.7",
        }
    body = "deviceType=mobile&username="+user+"&password="+Crypto().AESEncrypt(pwd)+"&verifyCode=&openId=&cookieBackup="
    r = requests.post(url,headers=headers,data=json.dumps(body))
    ken=r.text
    dir = json.loads(ken)
    return dir
    

    
    
    



# 获取课程信息
def get_course():
    url = 'https://server.gltu.cn/servicehall/backend/business/app/stuClassAttend/getStuClassAttend'
    headers = \
        {
            "Host": "server.gltu.cn",
            "Connection": "keep-alive",
            "Accept": "application/json, text/plain, */*",
            "X-XSS-Protection": "1",
            "X-Content-Type-Options": "nosniff",
            "isMobile": "1",
            "User-Agent": "Mozilla/5.0 (Linux; Android 11; Mi 10 Pro Build/RKQ1.200826.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.72 MQQBrowser/6.2 TBS/045810 Mobile Safari/537.36 MMWEBID/94 MicroMessenger/8.0.10.1960(0x28000A30) Process/toolsmp WeChat/arm32 Weixin NetType/5G Language/zh_CN ABI/arm64",
            "token": get_token()['RetData']['sid'],
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://server.gltu.cn/wap/serve_special?id\u003d1245\u0026customized\u003dSignAll\u0026code\u003d011wPJ0w3UIg8Y2yHq2w3Ob09l4wPJ0-\u0026state\u003d",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q\u003d0.9,en-US;q\u003d0.8,en;q\u003d0.7"
        }

    i = requests.get(url=url, headers=headers)
    xinxi = i.text
#    print(xinxi)
    xx = json.loads(xinxi)
#    print(xx)
    return xx



#模拟扫码
def saoma():
    url = 'https://server.gltu.cn/servicehall/backend/business/app/stuClassAttend/codeConfirm'
    headers = \
        {
            "Host": "server.gltu.cn",
            "Connection": "keep-alive",
            "Content-Length": "151",
            "Accept": "application/json, text/plain, */*",
            "X-XSS-Protection": "1",
            "X-Content-Type-Options": "nosniff",
            "isMobile": "1",
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 11; zh-cn; Mi 10 Pro Build/RKQ1.200826.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36 XiaoMi/MiuiBrowser/15.9.16 swan-mibrowser",
            "token": get_token()['RetData']['sid'],
            "Content-Type": "application/json;charset\u003dUTF-8",
            "Origin": "https://server.gltu.cn",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://server.gltu.cn/wap/serve_special?id\u003d1245\u0026customized\u003dSignAll\u0026code\u003d051Vbp0w3KlVbY2LZx1w3eJR6Z2Vbp00\u0026state\u003d",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q\u003d0.9,en-US;q\u003d0.8,en;q\u003d0.7",
            "Cookie": "CASTGC\u003dTGT-398006-fdHvTe3ebYOHhN6pT6QC0OntYCUJB94MUCD9h4Wpod1ml7D3Qg1648081215859-sFlQ-cas"
        }

    body = \
        {
            "lat": "25.13232198606", "lng": "110.3078869244", "roomId": roomId, "attendId": id, "location": "火星",
            "signType": 0
        }
    s = requests.post(url=url, headers=headers, json=body)
    sm = s.text
#    print(headers)
    print(sm)
    
    
    
def qd():
    url = 'https://server.gltu.cn/servicehall/backend/business/app/stuClassAttend/updateAttendStatus'
    headers = \
        {
            "Host": "server.gltu.cn",
            "Connection": "keep-alive",
            "Content-Length": "132",
            "Accept": "application/json, text/plain, */*",
            "X-XSS-Protection": "1",
            "X-Content-Type-Options": "nosniff",
            "isMobile": "1",
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 11; zh-cn; Mi 10 Pro Build/RKQ1.200826.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36 XiaoMi/MiuiBrowser/15.9.16 swan-mibrowser",
            "token": get_token()['RetData']['sid'],
            "Content-Type": "application/json;charset\u003dUTF-8",
            "Origin": "https://server.gltu.cn",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://server.gltu.cn/wap/student/handleSign?signType\u003d0\u0026signStatusName\u003d%E5%BE%85%E7%AD%BE%E5%88%B0\u0026attendId\u003d" + str(
            id) + "\u0026roomId\u003d" + str(
            roomId) + "\u0026location\u003d%E7%81%AB%E6%98%9F",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q\u003d0.9,en-US;q\u003d0.8,en;q\u003d0.7",
            "Cookie": "CASTGC\u003dTGT-398006-fdHvTe3ebYOHhN6pT6QC0OntYCUJB94MUCD9h4Wpod1ml7D3Qg1648081215859-sFlQ-cas"
        }

    body = \
        {
            "lat": "", "lng": "", "roomId": roomId, "id": id, "lessonId": lessonId, "signType": 0, "signRemark": ""
        }
    q = requests.post(url=url, headers=headers, json=body)
    qd = q.text
#    print(headers)
    print(qd)



if int(get_token()['RetData']['code']) == 302:
    print("登录成功")
    xx = get_course()
    if xx["resData"] == None:
        print("暂无签到课程")
    else:
        roomId = xx["resData"]["roomId"]
        id = xx["resData"]["id"]
        lessonId = xx["resData"]["lessonId"]
        saoma()
        qd() 
else:
    print(get_token()['RetData']['msg'])
    
