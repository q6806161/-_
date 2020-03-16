import requests, random, time, rsa, hashlib, base64, re, json
from binascii import b2a_hex
from urllib.parse import quote
import redis

class WeiBo(object):
    
    def __init__(self):
        self.session = requests.Session()
        self.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36"
            }
    
    """登录模块"""
    def login(self, account, password):
        api = "https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)"
        nonce = self._get_nonce()
        servertime = self._get_now_time()
        sp = self._get_sp_rsa(password, servertime, nonce)
        su = self._get_su(account)
        data = {
            "entry": "weibo",
            "gateway": "1",
            "from": "",
            "savestate": "7",
            "qrcode_flag": "false",
            "useticket": "1",
            "pagerefer": "https://login.sina.com.cn/crossdomain2.php?action=logout&r=https%3A%2F%2Fpassport.weibo.com%2Fwbsso%2Flogout%3Fr%3Dhttps%253A%252F%252Fweibo.com%26returntype%3D1",
            "vsnf": "1",
            "su": su,
            "service": "miniblog",
            "servertime": servertime,
            "nonce": nonce,
            "pwencode": "rsa2",
            "rsakv": "1330428213",
            "sp": sp,
            "sr": "1920*1080",
            "encoding": "UTF - 8",
            "prelt": "149",
            "url": "https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
            "returntype": "META",
            }
        headers = self.headers.copy()
        headers.update({
            "Host": "login.sina.com.cn",
            "Origin": "https://weibo.com",
            "Referer": "https://weibo.com/"
            })
        response = self.session.post(api, headers=headers, data=data, allow_redirects=False)
        search_result = self._re_search("location.replace\(\"(.*?)\"", response.text)
        redirct_url = search_result and search_result.group(1)
        if not redirct_url:
            raise Exception("重定向url获取失败")
        response = self.session.get(redirct_url, headers=headers.update({
        "Referer": "https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)"}), allow_redirects=False)
        search_result = self._re_search('"arrURL":(.*?)}', response.text)
        redirct_urls = search_result and search_result.group(1)
        if not redirct_urls:
            raise Exception("重定向url获取失败")
        redirct_url_list = json.loads(redirct_urls)
        userId = ""
        for url in redirct_url_list:
            response = self.session.get(url, headers=self.headers)
            if url.startswith("https://passport.weibo.com/wbsso/login"):
                userId = self._re_search('"uniqueid":"(.*?)"', response.text).group(1)
        if not userId:
            raise Exception("userId获取失败")
        user_details_url = "https://weibo.com/u/{}/home?wvr=5&lf=reg".format(userId)
        response = self.session.get(user_details_url, headers={
            "Referer": "https://weibo.com/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36"
            })
        if self._re_search(userId, response.text):
            # 拿到userid放便登录主页
            print(f"{userId}登录成功")
            cookies_dict = requests.utils.dict_from_cookiejar(self.session.cookies)
            return [cookies_dict, userId]  # 返回cookies和用户id
            # self.session.get("https://s.weibo.com/weibo/%25E8%25A5%25BF%25E7%2593%259C?topnav=1&wvr=6&b=1&page=1")
        else:
            raise Exception(f"{userId}登录失败")
  
    """获得nonce参数"""
    def _get_nonce(self):
        nonce = ""
        random_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        for i in range(5):
            index = random.randint(0, len(random_str) - 1)
            nonce += random_str[index]
        return nonce
  
    """获得timestamp时间戳"""
    def _get_now_time(self):
        return str(int(time.time()))
  
    """rsa加密"""
    def _get_sp_rsa(self, password, servertime, nonce):
        key = "EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443"
        pubkey = rsa.PublicKey(int(key, 16), int("10001", 16))
        res = rsa.encrypt(bytes("" + "\t".join([servertime, nonce]) + "\n" + password, encoding="utf-8"), pubkey)
        return b2a_hex(res)
  
    """sha1加密"""
    def _get_sp_sha1(self, password, servertime, nonce):
        res = hashlib.sha1(bytes("" + hashlib.sha1(bytes(hashlib.sha1(bytes(password, encoding="utf-8")).hexdigest(),
        encoding="utf-8")).hexdigest() + servertime + nonce,encoding="utf-8")).hexdigest()
        return res
  
    """su参数加密算法"""
    def _get_su(self, account):
        return str(base64.b64encode(bytes(account, encoding="utf-8")), encoding="utf-8")
  
    """正则表达式"""
    def _re_search(self, pattern, html):
        return re.search(pattern, html, re.S)

class Redis_connection(object):
    
    def __init__(self):
        self.pool = redis.ConnectionPool(host='127.0.0.1', port=6379, db=2, decode_responses=True)   # host是redis主机，需要redis服务端和客户端都起着 redis默认端口是6379
        self.r = redis.Redis(connection_pool=self.pool)
        # 放入微博账号和密码
        self.username_tpl_ua_list = [
            {"account":"你的账号1",
            "password":"账号1密码"},
            {"account":"你的账号2",
            "password":"账号2密码"},
            {"account":"你的账号3",
            "password":"账号3密码"}
            ]
    
    """账号信息和cookies的初始化写入"""
    def hmset_account_password_cookies_init(self, cookies="", USERID=""):
        for item in self.username_tpl_ua_list:
            self.r.hmset("weibo:account_password",{item["account"]:item["password"]})     # key是"gender" value是"male" 将键值对存入redis缓存
            self.r.hmset("weibo:account_cookies",{item["account"]:cookies})
            self.r.hmset("weibo:account_USERID",{item["account"]:USERID})
    """cokies更新用"""
    def hset_cookies(self, account, cookies):
        self.r.hset("weibo:account_cookies", account, cookies)

    def hset_USERID(self, account, USERID):
        self.r.hset("weibo:account_USERID", account, USERID)

    """循环获得账号-检测和获取cookies的时候用"""
    def hget_account_password_get(self):
        return self.r.hkeys("weibo:account_password")
    
    """随机抽取账号-爬取的时候获取用"""
    def hget_account_crawl(self):
        return random.choice(self.r.hkeys("weibo:account_password"))

    """获取账号对应的密码"""
    def hget_password(self,account):
        return self.r.hget("weibo:account_password",account)
    
    """获取账号对应的cookies"""
    def hget_cookie(self,account):
        return self.r.hget("weibo:account_cookies", account)




if __name__ == '__main__':
    weibo = WeiBo()
    redis_con = Redis_connection()
    cookies_out_of_date_flag = False
    # 如果还没创建账号和密码redis键值表，则新建hash键值表，否则从账号密码库中取得账号
    if not redis_con.hget_account_password_get():
        redis_con.hmset_account_password_cookies_init() #写入账号和密码，账号和ua，账号和cookies
    # 获得账号和对应的密码
    account_list = redis_con.hget_account_password_get()
    for username in account_list:
        # 当无法登录或者cookies值为空字符时调用写入cookies程序
        if not redis_con.hget_cookie(username) or cookies_out_of_date_flag:
            password = redis_con.hget_password(username)
            weibocookiesdict, USERID = weibo.login(username,password)
            redis_con.hset_cookies(username,json.dumps(weibocookiesdict))
            redis_con.hset_USERID(username, USERID)
            print(f"{username}重新登录获取cookies成功")
            time.sleep(5)  # 避免账号切换过快触发反爬
        weibocookiesdict = json.loads(redis_con.hget_cookie(username))
        print(f"成功获取{username}的cookies")
        # return tuple(weibocookiesdict,cookies_out_of_date_flag)
