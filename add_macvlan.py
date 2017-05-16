from portal import PortalAuth
get_dict={}
post_dict={}
j=1
for i in range(35,60):
	get_dict["192.168.11.%s" %(i)]="www.qq.com"
	post_dict["192.168.11.%s" %(i)]=["tenda%s" %(j),"tenda%s" %(j)]
	j=j+1
t=PortalAuth(**get_dict)
t.config_macvlan()
