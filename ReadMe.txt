1、add_macvlan.py 主要用于在eth1上添加Macvlan 序号从veth1-vethN DUT IP地址最后一位为.1
2、auth.py 主要用于模拟发送请求认证 (需要先保证域名可达)
3、PortalAuth.py 主要函数文件
4、del_macvlan.py 主要用于删除Macvlan
5、默认保存结果为当前目录下的testresult.csv文件
6、最大只支持250个用户
#所需要安装的python包有requests requests_toolbelt
在python2.7.10上测试通过
