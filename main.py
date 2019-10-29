from selenium import webdriver
import http.cookiejar as cookielib
import requests
import time
driver = webdriver.Chrome("chromedriver")
driver.get("http://weibo.com")

cookie = cookielib.LWPCookieJar()
cookie.load('./cookies/cookie',ignore_discard=True,ignore_expires=True)
load_cookies = requests.utils.dict_from_cookiejar(cookie)
for k in load_cookies:
    tmpCookie = {"name":k,"value":load_cookies[k]}
    driver.add_cookie(tmpCookie)
driver.get("https://api.weibo.com/chat/#/chat?to_uid=1983693223&source_from=9")
