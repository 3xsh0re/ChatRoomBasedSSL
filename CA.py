# CA模块
# 1.CA自签名:openssl genrsa -des3 -out rootCA.key 2048
#           openssl req -new -x509 -key rootCA.key -days 365 -out rootCA.crt
# 2.其他端申请给证书签名:
# openssl genrsa -des3 -out req.key 2048
# openssl req -new -key req.key -out req.csr -days 365
# openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -in req.csr -out req.crt -days 365
#
import subprocess
import socket
import concurrent.futures
from pathlib import Path

CA_host = "47.93.254.31"
CA_port = 54321
CA_download_port = 12345
cert_num = 0


# 根证书生成
def Gen_rootCA():
    # 生成私钥
    subprocess.run(['openssl', 'genrsa', '-des3', '-passout', 'pass:3xsh0re', '-out', 'rootCA.key', '2048'])
    # 指定证书主题字段信息
    subject_info = "/C=CN/ST=Beijing/L=Haidian/O=USTB/OU=USTB_CA/CN=USTB.CA"
    # 生成自签名证书
    subprocess.run(
        ['openssl', 'req', '-new', '-x509', '-passin', 'pass:3xsh0re', '-key', 'rootCA.key', '-days', '365', '-out',
         'rootCA.crt', '-subj', subject_info], capture_output=True)

    print("\033[32m[+]\033[0m自签名证书生成完成")


# 为申请者生成证书
def Sign_Cert():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as CA_socket:
        CA_socket.bind(("0.0.0.0", CA_port))
        CA_socket.listen(1)
        print('\033[32m[+]\033[0m等待客户端连接...')
        while True:
            conn, addr = CA_socket.accept()
            print(f'\033[32m[+]\033[0m自{addr[0]}的申请者已连接')

            # 生成证书号
            global cert_num
            sig = f'{addr[0].replace(".", "")}_{addr[1]}_{cert_num}'
            cert_num += 1
            with conn:
                conn.settimeout(2)
                csr_data = b''
                while True:
                    try:
                        data = conn.recv(1024)
                        if len(data) == 0:
                            break
                        csr_data += data
                        pass
                    except socket.timeout:
                        break
                # 生成 req.csr 文件
                with open(f'req_{sig}.csr', 'wb') as csr_file:
                    csr_file.write(csr_data)
                print('\033[32m[+]\033[0m申请文件CSR接收成功')
                # 在这里处理证书请求文件的数据
                command = [
                    'openssl', 'x509',
                    '-req', '-CA', './rootCA.crt',
                    '-CAkey', 'rootCA.key',
                    '-CAcreateserial',
                    '-in', f'./req_{sig}.csr',
                    '-passin', 'pass:3xsh0re',
                    '-out', f'./req_{sig}.crt',
                    '-days', '365'
                ]
                print("\033[32m[+]\033[0m正在查验申请者资质......")
                print("\033[32m[+]\033[0m打印签发信息:")
                try:
                    subprocess.run(command, stdout=subprocess.DEVNULL)
                    print(f"\033[32m[+]\033[0m来自{addr[0]}的申请者的证书签署完成")
                except subprocess.CalledProcessError as e:
                    print("\033[31m[-]当前系统没有安装OpenSSL库\033[0m")

                # 传送CRT
                with open(f'./req_{sig}.crt', 'rb') as file:
                    while True:
                        data = file.read(1024)
                        if not data:
                            break
                        if conn.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                            conn.sendall(data)
                print('\033[32m[+]\033[0m证书发送完成!')
                conn.close()
                print('\033[32m[+]\033[0m本次签发结束!\n-------------------------------------------------------')


# CA提供根证书下载
def Download_rootCA():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as CA_Download_socket:
        CA_Download_socket.bind(("0.0.0.0", CA_download_port))
        CA_Download_socket.listen(1)
        print('\033[32m[+]rootCA下载端口开放中...\033[0m')
        while True:
            conn, addr = CA_Download_socket.accept()
            print(f'\033[32m[+]\033[0m自{addr[0]}的下载者已连接')
            # 传送rootCA.crt
            with open(f'./rootCA.crt', 'rb') as file:
                while True:
                    conn.settimeout(2)
                    data = file.read(1024)
                    if not data:
                        break
                    if conn.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                        conn.sendall(data)
            print('\033[32m[+]\033[0mrootCA.crt发送完成!\n---------------------------------------------------')
            conn.close()
    pass


# Client请求签发证书
def Client_Request_Cert(username, passwd):
    # 生成私钥
    command = ['openssl', 'genrsa', '-des3', '-passout', f'pass:{passwd}', '-out', f'{username}_req.key', '2048']
    subprocess.run(command)
    # 生成证书请求文件CSR
    subject_info = f"/C=CN/ST=Beijing/L=Haidian/O=USTB_{username}/OU=USTBer/CN=Client_{username}"
    command2 = ['openssl', 'req', '-new', '-key', f'{username}_req.key', '-passin', f'pass:{passwd}', '-out',
                f'{username}_req.csr', '-days', '365', '-subj', subject_info]
    subprocess.run(command2, capture_output=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((CA_host, CA_port))
        print('\033[32m[+]\033[0m已连接至CA服务器')
        print('\033[32m[+]\033[0m正在向CA发送签发请求.....')

        with open(f'./{username}_req.csr', 'rb') as file:
            while True:
                data = file.read(1024)
                if not data:
                    break
                client_socket.sendall(data)
        print('\033[32m[+]\033[0mCSR文件发送完成!\n'
              '\033[32m[+]\033[0m正在等待CA签发......')

        crt_data = b''
        while True:
            data = client_socket.recv(1024)
            if len(data) == 0:
                break
            crt_data += data
        # 生成 req.crt 文件
        with open(f'{username}_req.crt', 'wb') as csr_file:
            csr_file.write(crt_data)
        print(f'\033[32m[+]\033[0m证书{username}_req.crt制作完成,可在当前文件夹下查看')


# Client验证证书,若验证通过则在当前文件夹下生成服务端公钥
def Client_Verify():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((CA_host, CA_download_port))
        crt_data = b''
        while True:
            data = client_socket.recv(1024)
            if len(data) == 0:
                break
            crt_data += data
        # 生成 req.crt 文件
        with open('rootCA.crt', 'wb') as csr_file:
            csr_file.write(crt_data)
        print(f'\033[32m[+]\033[0mrootCA.crt下载完成,请在当前目录下查看')
        verify_command = ['openssl', 'verify', '-CAfile', './rootCA.crt', f'Server_req.crt']
        result = subprocess.run(verify_command, capture_output=True, text=True)
        if "OK" in result.stdout.strip():
            print("\033[32m[+]服务器证书验证成功!\033[0m")
            gen_server_pk_command = ['openssl x509 -in Server_req.crt -pubkey -noout > server_pk.pem']
            print("\033[32m[+]已经在当前文件夹下生成服务端公钥server_pk.pem!\033[0m")
            return 1
        else:
            print("\033[31m[-]验证失败！！！\033[0m")
            return 0


# Server请求签发证书
def Server_Request_Cert():
    try:
        # 生成私钥
        command = ['openssl', 'genrsa', '-des3', '-passout', f'pass:USTBServer', '-out', f'Server_req.key', '2048']
        subprocess.run(command, capture_output=True)
        # 生成证书请求文件CSR
        subject_info = f"/C=CN/ST=Beijing/L=Haidian/O=USTB_Server/OU=Server/CN=USTB_Server"
        command2 = ['openssl', 'req', '-new', '-key', f'Server_req.key', '-passin', f'pass:USTBServer', '-out',
                    f'Server_req.csr', '-days', '365', '-subj', subject_info]
        subprocess.run(command2, capture_output=True)
        print('\033[32m[+]\033[0mCSR文件生成成功!')
    except subprocess.CalledProcessError as e:
        print("\033[31m[-]私钥生成失败!!!\033[0m")
        print("\033[31m[-]查看当前系统是否安装OpenSSL库!!!\033[0m")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((CA_host, CA_port))
        print('\033[32m[+]\033[0m已连接至CA服务器')
        print('\033[32m[+]\033[0m正在向CA发送签发请求.....')

        with open(f'./Server_req.csr', 'rb') as file:
            while True:
                data = file.read(1024)
                if not data:
                    break
                client_socket.sendall(data)
        print('\033[32m[+]\033[0mCSR文件发送完成!\n'
              '\033[32m[+]\033[0m正在等待CA签发......')

        crt_data = b''
        while True:
            data = client_socket.recv(1024)
            if len(data) == 0:
                break
            crt_data += data
        # 生成 req.crt 文件
        with open(f'Server_req.crt', 'wb') as csr_file:
            csr_file.write(crt_data)
        print(f'\033[32m[+]\033[0m证书Server_req.crt制作完成,可在当前文件夹下查看')


# Server 请求验证客户端证书
def Server_Verify(username):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((CA_host, CA_download_port))
        crt_data = b''
        while True:
            data = client_socket.recv(1024)
            if len(data) == 0:
                break
            crt_data += data
        # 生成 req.crt 文件
        with open('rootCA.crt', 'wb') as csr_file:
            csr_file.write(crt_data)
        print(f'\033[32m[+]\033[0mrootCA.crt下载完成,请在当前目录下查看')
        verify_command = ['openssl', 'verify', '-CAfile', './rootCA.crt', f'{username}_req.crt']
        result = subprocess.run(verify_command, capture_output=True, text=True)
        if "OK" in result.stdout.strip():
            print("\033[32m[+]目标客户端证书验证成功!\033[0m")
            return 1
        else:
            print("\033[31m[-]验证失败！！！\033[0m")
            return 0


# CA端
def CA():
    print('\033[34m _   _ ____ _____ ____     ____    _    \033[0m\n'
          '\033[34m| | | / ___|_   _| __ )   / ___|  / \   \033[0m\n'
          '\033[34m| | | \___ \ | | |  _ \  | |     / _ \  \033[0m\n'
          '\033[34m| |_| |___) || | | |_) | | |___ / ___ \ \033[0m\n'
          '\033[34m\___/ |____/ |_| |____/___\____/_/   \_\ \033[0m\n')
    print("\t\t\t\t\033[34m-------created by 3xsh0re\033[0m")
    root_ca_file = Path("rootCA.crt")
    if root_ca_file.is_file():
        print("\033[32m[+]rootCA.crt已经生成\033[0m")
    else:
        # 生成根证书
        Gen_rootCA()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交线程1的执行
        thread1 = executor.submit(Download_rootCA)
        # 提交线程2的执行
        thread2 = executor.submit(Sign_Cert)

        # 等待两个线程执行完成
        concurrent.futures.wait([thread1, thread2])


# Client端请求CA颁发证书
# Client_Request_Cert("ZZR", "123456")
# 用户验证Server
# Client_Verify()

# Server端请求CA颁发证书
# Server_Request_Cert()
# Server验证用户ZZR
# Server_Verify("ZZR")

# CA端
# CA()
