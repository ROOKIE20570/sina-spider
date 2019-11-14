import login
import requests
import urllib.parse as urlParse
import json


def getWeiboAboutTitle(title: str, page : int):
    typeEncoded = urlParse.quote("type=1&q=" + title + "page="+str(page))
    url = "https://m.weibo.cn/api/container/getIndex?containerid=100103" + typeEncoded + "&page_type=searchall"
    try:
        res = requests.get(url)
        if res.status_code != 200:
            raise
    except Exception as e:
        print("request error")

    data = json.loads(res.text)
    weiboCards = data['data']['cards']

    filterCards = []
    for weiboCard in weiboCards:
        #只筛选
        if weiboCard['card_type'] == 9:
            filterCards.append(weiboCard)

    return weiboCards

