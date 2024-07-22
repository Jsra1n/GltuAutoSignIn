# coding = utf-8
from urllib.request import urlretrieve
from Crypto.Cipher import AES
import datetime
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



#登录
def Login(user,pwd):
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
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 12; zh-cn; unknown Build/RKQ1.200826.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36/Browser/15.9.16 swan-mibrowser",
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
    token = dir["RetData"]["sid"]
    return dir
    print(dir)


def get_student(token):
    url = "https://server.gltu.cn/servicehall/backend/web/getUserInfo?token="+token
    headers = \
        {
            "Host": "server.gltu.cn",
            "Connection": "keep-alive",
            "Accept": "application/json, text/plain, */*",
            "X-XSS-Protection": "1",
            "X-Content-Type-Options": "nosniff",
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 12; zh-cn; unknown Build/RKQ1.200826.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36/Browser/15.9.16 swan-mibrowser",
            "isMobile": "1",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://server.gltu.cn/wap/",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q\u003d0.9,en-US;q\u003d0.8,en;q\u003d0.7",
        }

    s = requests.get(url=url, headers=headers)
    stu = json.loads(s.text)
    return stu
    print(stu)




# 获取课程信息
def get_course(token):
    url = 'https://server.gltu.cn/servicehall/backend/business/app/stuClassAttend/getStuClassAttend'
    headers = \
        {
            "Host": "server.gltu.cn",
            "Connection": "keep-alive",
            "Accept": "application/json, text/plain, */*",
            "X-XSS-Protection": "1",
            "X-Content-Type-Options": "nosniff",
            "isMobile": "1",
            "User-Agent": "Mozilla/5.0 (Linux; Android 12; unknown Build/RKQ1.200826.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.72 MQQBrowser/6.2 TBS/044605 Mobile Safari/537.36 MMWEBID/94 MicroMessenger/8.0.10 Process/toolsmp WeChat/arm32 Weixin NetType/WiFi Language/zh_CN ABI/arm64",
            "token": token,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://server.gltu.cn/wap/serve_special?id\u003d1245\u0026customized\u003dSignAll\u0026code\u003d011wPJ0w3UIg8Y2yHq2w3Ob09l4wPJ0-\u0026state\u003d",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q\u003d0.9,en-US;q\u003d0.8,en;q\u003d0.7"
        }

    i = requests.get(url=url, headers=headers)
    xinxi = i.text
    xx = json.loads(xinxi)
    return xx



#模拟扫码
def saoma(token,roomId,id):
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
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 12; zh-cn; unknown Build/RKQ1.200826.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36/Browser/15.9.16 swan-mibrowser",
            "token": token,
            "Content-Type": "application/json;charset\u003dUTF-8",
            "Origin": "https://server.gltu.cn",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://server.gltu.cn/wap/serve_special?id\u003d1245\u0026customized\u003dSignAll\u0026code\u003d051Vbp0w3KlVbY2LZx1w3eJR6Z2Vbp00\u0026state\u003d",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q\u003d0.9,en-US;q\u003d0.8,en;q\u003d0.7",
        }

    body = \
        {
            "lat": "25.13232198606", "lng": "110.3078869244", "roomId": roomId, "attendId": id, "location": "桂林旅游学院(雁山校区)",
            "signType": 0
        }
    s = requests.post(url=url, headers=headers, json=body)
    sm = s.text
    print(sm)
    
    
    
def qd(token,roomId,id,lessonId):
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
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 12; zh-cn; unknown Build/RKQ1.200826.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36/Browser/15.9.16 swan-mibrowser",
            "token": token,
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
        }

    body = \
        {
            "lat": "", "lng": "", "roomId": roomId, "id": id, "lessonId": lessonId, "signType": 0, "signRemark": ""
        }
    q = requests.post(url=url, headers=headers, json=body)
    qd = q.text
    print(qd)




def add_user():
    user = input("请输入学号：" )
    pwd = "Gltu175512"
    login = Login(user,pwd)
    ini = {'user': user, 'pwd': pwd, 'token': login["RetData"]["sid"]}
    if login["RetData"]["code"] == "302":        
        with open('a.ini', 'a', encoding='utf-8') as f:
            f.writelines(str(ini) +"\n")
            print(str(user)+"添加成功")
        return True       
    else:
        print(login)
        return False
 
            
                       
                                         



def qiandao():
    f= open("a.ini",'r',encoding= 'UTF-8')
    for i in f:    
#        token = eval(i)["token"]  #token登录
#        user = "202036610235" 
#        pwd = "Gltu142519"
        user = eval(i)["user"]
        pwd = eval(i)["pwd"]
        duetime = eval(i)["duetime"]
        last_time = datetime.datetime.strptime(duetime, '%Y-%m-%d')
        now_time = datetime.datetime.strptime(datetime.datetime.now().strftime('%Y-%m-%d'), '%Y-%m-%d')
        if now_time>last_time:       
            print(user+'已到期')
        else:        
            login = Login(user,pwd)
            token = login["RetData"]["sid"]
            stu = get_student(token)
            xx = get_course(token)
            print(xx)          
            if xx["resCode"] == "0":
        
                if xx["resData"] == None:
                    print("未找到签到课程")
                else:            
                    roomId = xx["resData"]["roomId"]
                    id = xx["resData"]["id"]
                    lessonId = xx["resData"]["lessonId"]
                    print("学生："+str(stu["RetData"]["deptName"])+str(stu["RetData"]["userName"])+"\n学号："+str(stu["RetData"]["userId"])+"\n课程："+str(xx["resData"]["lessonName"])+"\n教室："+str(xx["resData"]["roomName"])+"\n老师："+str(xx["resData"]["teacherName"]))
                    saoma(token,roomId,id)
                    qd(token,roomId,id,lessonId)
                                                   
                
            elif xx["resCode"] == "2":
                print(xx["resMsg"])
                






def get_name(user):
#    user = input("请输入ID: ")
    pwd = "66666666"
    token = Login(user,pwd)["RetData"]["sid"]
    url = "https://server.gltu.cn/servicehall/backend/check/userPassCheck"
    headers = \
        {
            "Host": "server.gltu.cn",
            "Connection": "keep-alive",
            "Accept": "application/json, text/plain, */*",
            "X-XSS-Protection": "1",
            "X-Content-Type-Options": "nosniff",
            "isMobile": "1",
            "User-Agent": "Mozilla/5.0 (Linux; Android 12; unknown Build/RKQ1.200826.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.72 MQQBrowser/6.2 TBS/044605 Mobile Safari/537.36 MMWEBID/94 MicroMessenger/8.0.10 Process/toolsmp WeChat/arm32 Weixin NetType/WiFi Language/zh_CN ABI/arm64",
            "token": token,             
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://server.gltu.cn/wap/serve_special?id\u003dobj_6543cc6d131234a2a5f0a2e291191364\u0026customized\u003dpassCheck",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q\u003d0.9,en-US;q\u003d0.8,en;q\u003d0.7"
        }
    a = requests.get(url=url, headers=headers)
    aaa = json.loads(a.text)
    print(aaa)
    return aaa

def get_p():
    id = ("请输入ID: ")
    pw = ("请输入密码: ")
    url = "https://photos2.gltu.cn//blade-auth/oauth/token"
    headers = \
        {
            "Host": "photos2.gltu.cn",
            "Connection": "keep-alive",
            "Content-Length": "99",
            "authorization": "Basic c2FiZXI6c2FiZXJfc2VjcmV0",
            "charset": "utf-8",
            "User-Agent": "Mozilla/5.0 (Linux; Android 12; unknown Build/RKQ1.200826.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.72 MQQBrowser/6.2 TBS/044605 Mobile Safari/537.36 MMWEBID/94 MicroMessenger/8.0.10 Process/toolsmp WeChat/arm32 Weixin NetType/WiFi Language/zh_CN ABI/arm64",
            "content-type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip,compress,br,deflate",
            "Referer": "https://servicewechat.com/wxcbb12fc26e344dac/3/page-frame.html"
        }
     
    body = "tenantId=948288&username="+id+"&password="+Crypto().Md5(pw)+"&grant_type=password"
    r = requests.post(url,headers=headers,data=body)
    p = json.loads(r.text)
    print(p)



def pao():
    grade = input("请输入年级: ")
    bh = int(input("请输入开始编号: "))
    bh2 = int(input("请输入结束编号: "))
#fw = int(input("请输入人数开始范围: "))
#fw2 = int(input("请输入人数结束范围: "))

    for j in range(bh,bh2):

        for i in range(1,60):
#num = input("请输入号码: ")
            user = grade+str(j).rjust(6,'0')+str(i).rjust(2,'0')



#登录        
            dir = get_name(user)
            if dir['resCode'] == '0':
                print(user+"登录成功")

 
            else:
                print(user+"登录失败，账号或密码错误")
                print(str(dir['resCode']))






def main():
    # 添加账号
    #add_user()  
    # 签到
    qiandao()
    
    #获取信息
    
    #get_p()
    #pao()



if __name__ == '__main__':
    main()
