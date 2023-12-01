# -*- coding = utf-8 -*-
# @Time : 2023/12/01
# @Author : cdbc
# @File :xui_weak_pass.py

import requests
import urllib3
from multiprocessing import Pool

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
        headers = {"Sec-Ch-Ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"94\"",
                   "Accept": "application/json, text/plain, */*",
                   "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                   "X-Requested-With": "XMLHttpRequest", "Sec-Ch-Ua-Mobile": "?0",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                                 "Chrome/94.0.4606.81 Safari/537.36",
                   "Sec-Ch-Ua-Platform": "\"Windows\"", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        pass_test = ["admin123", "admin", '123456', "123123", "admin888"]
        for password in pass_test:
            # 更新字典中的密码
            data = {"username": "admin", "password": password}
            try:
                res = requests.post(check_url, data=data, proxies=proxies, headers=headers, timeout=10)
                self._cache.add(check_url)
                if res.status_code == 200 and "true" in res.text:
                    with open(self._result_file, "a", encoding="utf-8") as f:
                        f.write(f"{url}\n")
                        print(f"{url} 该链接存在弱口令访问情况,密码为'{password}',请及时修复！")
                        f.close()
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
