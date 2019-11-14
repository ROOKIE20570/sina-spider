import requests
import json
import login



def sendText(uid: str, text: str, session):
    configUrl = "https://m.weibo.cn/api/config"
    try:
        configRes = session.get(configUrl)
        if configRes.status_code != 200:
            raise Exception('请求失败')
        config = json.loads(configRes.text)
        if config['data']['login'] != True:
            raise Exception("未登录")

        st = config['data']['st']

        chatUrl = "https://m.weibo.cn/api/chat/send"

        sent = session.post(chatUrl, {'content': text, "uid": uid, st: st},
                            headers={"x-xsrf-token": st, 'x-requested-with': "XMLHttpRequest",
                                     'referer': "https://m.weibo.cn/message/chat?uid=" + uid + "&name=msgbox"})
        print(sent.text)
    except Exception as e:
        print(e)

