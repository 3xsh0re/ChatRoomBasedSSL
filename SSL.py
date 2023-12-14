import hashlib
import random
import CA


# 模拟服务器和客户端
class Server:
    def __init__(self):
        self.generate_certificate()

    def generate_certificate(self):
        # 生成服务器的证书
        CA.Server_Request_Cert()

    def respond_to_client_hello(self, client_hello):
        # 模拟服务器响应客户端的Hello消息
        server_hello = "ServerHello"
        print("\033[32m[SSL]\033[0m服务器响应客户端的Hello消息")
        return server_hello

    def verify_client_certificate(self, username):
        # 服务器验证客户端的证书
        # 在实际应用中，这里会包含对CA证书链的验证逻辑
        return CA.Server_Verify(username)

    def generate_shared_secret(self):
        # 服务器生成共享密钥
        shared_secret = hashlib.sha256(self.private_key.encode()).hexdigest()
        return shared_secret


class Client:
    def __init__(self, username, passwd):
        self.pre_master_secret = str(random.randint(1, 1000))
        self.generate_certificate(username, passwd)

    def generate_certificate(self, username, passwd):
        # 生成客户端的证书
        print("\033[32m[SSL]\033[0m开始生成客户端的证书")
        CA.Client_Request_Cert(username, passwd)

    def send_client_hello(self,name):
        # 客户端发送Hello消息及证书
        client_hello = name
        print("\033[32m[SSL]\033[0m客户端发送Hello消息")
        return client_hello

    def process_server_hello(self, server_hello):
        # 客户端处理服务器的Hello消息
        shared_secret = hashlib.sha256(self.pre_master_secret.encode()).hexdigest()
        return shared_secret

    def verify_server_certificate(self):
        # 客户端验证服务器的证书
        # 在实际应用中，这里会包含对CA证书链的验证逻辑
        return CA.Client_Verify()


# 模拟SSL握手过程
def perform_ssl_handshake():
    server = Server()
    client = Client("zzr", "123456")

    # 客户端发送Hello消息
    client_hello = client.send_client_hello(name)
    print("\033[32m[SSL]\033[0m客户端发送Hello消息")

    # 服务器响应客户端的Hello消息
    server_hello = server.respond_to_client_hello(client_hello)
    print("\033[32m[SSL]\033[0m服务器响应客户端的Hello消息")

    # 服务器验证客户端的证书
    print("\033[32m[SSL]\033[0m服务器验证客户端的证书")
    client_certificate_verified = server.verify_client_certificate("zzr")

    if not client_certificate_verified:
        print("\031[32m[SSL]\033[0m客户端证书验证失败")
        return
    else:
        print("\033[32m[SSL]\033[0m客户端证书验证成功")

    # 客户端处理服务器的Hello消息，生成共享密钥
    print("\033[32m[SSL]\033[0m客户端处理服务器的Hello消息，生成共享密钥")
    shared_secret = client.process_server_hello(server_hello)

    # 客户端验证服务器的证书
    print("\033[32m[SSL]\033[0m客户端验证服务器的证书")
    server_certificate_verified = client.verify_server_certificate()

    if not server_certificate_verified:
        print("\033[31m[SSL]\033[0m服务器证书验证失败")
        return
    else:
        print("\033[32m[SSL]\033[0m服务器证书验证成功")

    # 输出共享密钥
    print("\033[32m[SSL]\033[0m共享密钥:", shared_secret)


# 执行SSL握手过程
# perform_ssl_handshake()
