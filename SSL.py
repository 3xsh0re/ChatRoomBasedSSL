import hashlib
import CA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes


# 加密函数
def encrypt_message(message, recipient_public_key):
    ciphertext = recipient_public_key.encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


# 解密函数
def decrypt_message(encrypted_message, recipient_private_key):
    plaintext = recipient_private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")


public_key_str = """-----BEGIN CERTIFICATE-----
MIIDVTCCAj0CFDhHwRNW+aLuZsTepzd7C8uWBMf6MA0GCSqGSIb3DQEBCwUAMGQx
CzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlkaWFu
MQ0wCwYDVQQKDARVU1RCMRAwDgYDVQQLDAdVU1RCX0NBMRAwDgYDVQQDDAdVU1RC
LkNBMB4XDTIzMTIxNTE0NDQ1NFoXDTI0MTIxNDE0NDQ1NFowajELMAkGA1UEBhMC
Q04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0hhaWRpYW4xETAPBgNVBAoM
CFVTVEJfWlpSMQ8wDQYDVQQLDAZVU1RCZXIxEzARBgNVBAMMCkNsaWVudF9aWlIw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDs8BlqQBQ5TKLI2qjEXYcO
LucVCQtdyfFcrPnAC2+98qH9KBtrnYTPepQtTuNFDVDNCrD27yT3ko6sunu1F1b/
Ian8xdpNGPgrps9wH6p7HeLn/q5c7xCOwApdWzX1eXRWmQmOy5rH/I0Lh8Kac38U
7g7yVXxe/yCiquJRgQlkJ5euJVbLRFfp8xPXcebvYOkLE5X79qXJWwlU2xsibp93
pIO5Pdu0IpO0rTDV0L7wu5DeAv9DOo8CyIv2vxZaaFZeeQ/IyR9LkwdZX5FGfJBP
A6ho2JfAE7lrH4CMLcrd4Je88RF9pxIGJAUVcWcDsCyuwQSWT27+RgR+afKBuKFx
AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKcm9ukA0pOQKM7uO55v3cxtRUOKKpjB
zCPei99Jm/6jFwE/YtgcsOlm83zgQBWMzJAtEV5Z9CYho6Nkc3sVeOVFDQGPqDMG
bJNKSriFig+iCh4JTaMqbQK/OUQHxnMuf9eG9dXAREBuwa5lisKxVEPVuHLhOgGc
3YSDA6y9Ljm71rYSmRTUu1jNVqva2w+wudBn6XxURXU8F/fWt89XgfY9Jnni55VO
EdahkQV/QrvBzf0sM1NHI8IWmyOxQB6haUwXCrTEfS9SyzQb3YKflYPEfsjtkHST
BXswpaSVhZKghS/98CtMQCn4VGC+kQfV1i7Yxm4jt9ESWOY4plZVN/k=
-----END CERTIFICATE-----"""


private_key_str = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,560DF54D1E103876

nnz1Rlcfa+rc8sQJBqO0ImO+DEsGgcu+TI7juwCVUwFWw0yYqwQlGGB/73iHlHxl
+KmVy8etagy6+A+hzTVVY6lBapbYcgH05/2xjmi6aT7PFDtQPAktjhppS5JIH6Gq
J3z/m1hlWXXJC09F8HUMhv7+KbFvO9G9db0iI4QFkEc/c9eo9RahBND/RIgPI6dX
7bhXtRYgLOjkqJOhktJ5ssJuJzPuAN6jspEHc21Ygf3Ygc+2GdqEqgFjhndBo3VV
Ar5n5pk9cTuTZrvO9NLKKzbXMInHUreert/pPCsQtCyp27iaX+5MfRAogA4EkCbl
FdXj2/ZNRboINgs3CVH7+kkTLTCPRuccTgwuUBEWQJOXzt7SKmofR0d6VMNnG7le
Km31qWS1mVjtVNaGV4Nw1wXNdUPQmpYmT2fgihzIvUNgo/zNGVno09NfcoSPLZTR
FUOMgW4hkAzlTvfLbcVYPhUWqbIIycxjnNlvJCW00JYIJI2w7MMZOS8itxF8/x5l
nIZ7qpQCiB2rhbHLJ0m1g3l8eE5y07Tft8/5etj+FnD8U8g55KoLWCVqV9+udyv/
ihpzAP2O+HIijBCMsbGW0JnKTg186FwdboAvub9AyYIKEJ772VWguy2h3XATNQvm
iI2bPrAtbdfZbdmZUJ2eSclqpUqLGnuasvD01HO1MxTYfwbTrmmnPrJaJVt9cEhA
d3lespCIBGXz8/wzBcWZsN3buReiIHV152wB6HeQmZtImn6N/Lmcqh4cqxlAH9w+
LS+MInZQgExMlRWrKrsjIyqrHKB1ZBmB8FL/56rWNIPOS5nq+VrhAS1f+0Qs2iuH
gEbJ69osobIcyY08t2yf/GQEOSXSIWI8pGOOUtY+bRRyGsiXp+ZZk/zQ2RP1e2GS
ISwEAsSrJyqjxjqVBtd4rl1vmI8tDpTFxdCigyYHCzFX+vWAB51Lb4btWQzmJ6oD
2q6fT6cfBy9LVLCu+xR/4Y4aP64bOxTBJmkrzKtq9AYYhw9bIdccBaWdrm3fN1T1
xK2qC++ZpspLzv4m6K7F4824nhi2qd790Wg84C+nrsCAeNwk7uL/d4IFggAVkSFd
Nc5p/UjIlULm/O/ijd/DrJOAXE1TxKNz1CbMCWovPqCbfsJ91QB0V47ErgWrFosq
H0F/40Azolzqxm+d5cn+sSVhU2jYi+/W47HY6/P9bQ0wVrXFEvDAlFkaI+Ot1PEE
0KvkY2TLFTrrFsoJ1s+zmWZQprJGeD9txB0+M3TENK3u5MdLSbVvFnpcmtDhpIma
O8AoXsUc8jwyT3VGx/sCOku3O6eJ4hiil/TByZTD9saT7Vahv8K7V82/+TqICWCz
fhtYV5pEsXerUZwRlC4Af8O32ExcdqCK72RSajE/8HYNcvfChH3Ucnsq7AEz0YFn
ZR/QdgNAhdeJ+uhRISRNm+glk2Ku1EopzxvVr9124I7/oWjHzUpd7REwQc+99ixM
pEkyM6jLty5qczt0Mg6Xmr+aJwY4jCJQi9QpW2jCT6L+w5lct+5Sdrh9fdK2t+ht
dFuYMcsa9CO8rqp3nTNbIKJ9yDISstomnIZGd4657Nzw11fnNnlC0csa5CO1HFMl
-----END RSA PRIVATE KEY-----
"""

public_key_bytes = public_key_str.encode("utf-8")
private_key_bytes = private_key_str.encode("utf-8")

# 将字节表示的公钥和私钥转换为对象
public_key = serialization.load_pem_x509_certificate(
    public_key_bytes, default_backend()
).public_key()
private_key = serialization.load_pem_private_key(
    private_key_bytes, password=None, backend=default_backend()
)


message_to_encrypt = "喵，这是一条秘密信息"
encrypted_message = encrypt_message(message_to_encrypt, public_key)
print(f"加密后的消息: {encrypted_message}")

decrypted_message = decrypt_message(encrypted_message, private_key)
print(f"解密后的消息: {decrypted_message}")


# 模拟服务器和客户端
class Server:
    def __init__(self):
        self.generate_certificate()

    def generate_certificate(self):
        # 生成服务器的证书
        CA.Server_Request_Cert()

    def respond_to_client_hello(self, client_hello):
        # 模拟服务器响应客户端的Hello消息
        server_hello = "Hello, " + str(client_hello) + ", I'm server."
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
        self.generate_certificate(username, passwd)

    def generate_certificate(self, username, passwd):
        # 生成客户端的证书
        print("\033[32m[SSL]\033[0m开始生成客户端的证书")
        CA.Client_Request_Cert(username, passwd)

    def send_client_hello(self, name):
        # 客户端发送Hello消息及证书
        client_hello = name
        print("\033[32m[SSL]\033[0m客户端发送Hello消息")
        return client_hello

    def process_server_hello(self, server_hello):
        # 客户端处理服务器的Hello消息
        shared_secret = hashlib.sha256(server_hello.encode()).hexdigest()
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
    client_hello = client.send_client_hello("zzr")
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
