#!/bin/bash
#description:according to the domain list to find the dns zone transfer vulnerability.
#Tyr Chen
#2015-2-6
if [ "$#" -ne "1" ];then				#判断命令行参数
	echo "usage: $0 doman-list-file"	
	exit 1
fi
THREAD=200						#线程数量
tmp_fifo="/tmp/$$.fifo"
tmp_fifo2="/tmp/$$.$$.fifo"
mkfifo $tmp_fifo 					#创建FIFO管道
mkfifo $tmp_fifo2
exec 6<>$tmp_fifo 					#定义文件描述符6为指定管道
exec 7<>$tmp_fifo2
echo 1 >&7						#将数字1压入管道(描述符7)
rm $tmp_fifo 							
rm $tmp_fifo2
for((j=0;j<$THREAD;j++))				#压入指定数量的换行符到管道(描述符6)
do
    echo >&6
done 
count=`cat $1|wc -l`					#统计域名数量
declare -x pro=1
echo "共有域名$count个"
test -d dnslist || mkdir dnslist
test -e host.txt && rm host.txt
test -e log.txt  && rm log.txt
test -e log.err  && rm log.err
log="./log.txt"
errlog="./log.err"
dig_domain(){
        line=${1#*.}					#这里给定的域名都是都有www的，因此去除最前面的'www.'
        nsserver=`dig +short ns $line`			#dig ns记录 解析指定域名的namserver
		echo "$line" >> $log
        echo -e "发现DNS服务器:" >> $log
        echo -e "\033[33m$nsserver\033[0m" >>$log
        for ns in $nsserver
        do  
                echo -e "\t正在与服务器$ns尝试区域传送..." >>$log
 				echo -e "\tdomain=$line   nsserver=@$ns" >>$log
                if dig +time=1 axfr $line @$ns 2>>$errlog | tee "./dnslist/$line.txt" | grep -q "SERVER:";then #尝试区域传送
                        flag=success
						echo -e "\t服务器$ns传送成功" >> $log
						echo $ns >> host.txt
                else
						flag=fail
						echo -e "\t服务器$ns传送失败" >> $log
                        test -e "./dnslist/$line.txt" && rm "./dnslist/$line.txt" 2>>$errlog
                fi  
        done
 	echo -ne "\033\033[100D" 			#光标移到行首
 	read -u7 pro
 	echo $((pro+1)) >&7
 	pec=`expr $((pro)) \* 100 / $count`		#计算当前进度
 	echo -ne "当前进度: $pec%\t" 
 	printf "%-20s" $line
	if [ "$flag" == "success" ];then  		#最后显示是防止多线程输出不同步的问题
		printf "\033[31m%s\033[0m" "传送成功"	#中间的\033是控制字符，后面指定文字颜色
	else
		printf "\033[36m%s\033[0m" "传送失败"
	fi
	echo -ne "\033[36m\033[K"			#清除从光标到行尾的内容 
	echo -ne "\033\033[100D" 			#光标移到行首
}
while read line    					#while循环使用read来读取文件每一行的内容
do
	read -u6					#从管道中读取一个字符
	{
		dig_domain $line	#执行测试函数
		echo >&6 			#写入一个字符
	}&						#放入后台运行
	pid=$!						#此处的$!为最后运行的后台process ID
done <$1          					#接收来自文件的输入
wait							#wait等待所有后台程序全部执行完毕
exec 6>&-						#关闭文件描述符
exec 7>&-
echo
echo "done"
echo "`wc -l host.txt| cut -d ' ' -f1`个dns服务器存在区域传送漏洞.列表见 host.txt"
echo "`ls -l dnslist | grep -v totol | wc -l`个域名存在风险.区域传送记录见 dnslist目录"
echo "ps:log.txt记录运行过程中产生的正常日志,log.err记录错误解析日志"
exit 0
