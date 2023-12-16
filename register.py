import random
import sqlite3
import hashlib
import logging
import re
from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
from need_module import sys
'''
注册新用户时，使用了hashlib.sha256对密码进行哈希处理，并将哈希后的密码存储到数据库中。
注册限制密码至少包含一个大、小写字母、数字和特殊字符(@$!%*?&)，长度不能小于8个字符
登录失败限制：限制用户连续登录失败次数，超过设定次数后锁定账号1min，防止暴力破解密码。
使用了sqlite3模块进行数据库连接，并通过参数化查询来避免SQL注入漏洞。
增加日志记录功能，记录用户的注册行为和异常情况。
'''
class Register(object):
    def __init__(self, Login,Chat,master=None):
        self.root = master  # 定义内部变量root
        self.root.title('注册')
        self.Login=Login
        self.Chat=Chat
        #new
        self.valid_users = {}  # 初始化valid_users字典
        # 设置日志记录器
        self.logger = logging.getLogger('registration')
        self.logger.setLevel(logging.DEBUG)

        # 创建一个文件处理器，将日志写入到文件中
        file_handler = logging.FileHandler('registration.log')
        file_handler.setLevel(logging.DEBUG)

        # 创建一个格式化器，定义日志的格式
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # 将格式化器添加到文件处理器中
        file_handler.setFormatter(formatter)

        # 将文件处理器添加到日志记录器中
        self.logger.addHandler(file_handler)

        # 设置窗口居中
        sw = self.root.winfo_screenwidth()  # 计算水平距离
        sh = self.root.winfo_screenheight()  # 计算垂直距离
        w = 690  # 宽
        h = 505  # 高
        x = (sw - w) / 2
        y = (sh - h) / 2
        self.root.geometry("%dx%d+%d+%d" % (w, h, (x + 160), y))
        self.root.iconbitmap(r'images/icon/register.ico')  # 设置左上角窗口图标
        self.root.resizable(0, 0)  # 窗口设置为不可放大缩小
        self.creatregister()

    def creatregister(self):
        self.fr2 = Frame(self.root)
        self.fr2.place(x=0, y=0, width=690, height=400)
        self.fr1 = Frame(self.root)
        self.fr1.place(x=240, y=300, width=400, height=210)


        self.benner_img = 'images/benner/bg.png'

        # 图片大小：690x300
        self.pic = Image.open(self.benner_img).resize((690, 400))
        self.register_benner = ImageTk.PhotoImage(self.pic)

        # 标签 图片
        self.imgLabel = Label(self.fr2, image=self.register_benner)
        self.imgLabel.pack()

        # 标签 用户和密码
        self.label_usr = Label(self.fr1, text="用户名：", font=("宋体", 11))
        self.label_usr.grid(row=0, column=0)
        self.label_pwd = Label(self.fr1, text="密  码：", font=("宋体", 11))
        self.label_pwd.grid(row=1, column=0, pady=5)
        self.label_repwd = Label(self.fr1, text="确认密码：", font=("宋体", 11))
        self.label_repwd.grid(row=2, column=0)

        # 文本框 用户名
        self.var_usr_name = StringVar()
        self.entry_name = Entry(self.fr1, textvariable=self.var_usr_name, font=("宋体", 11))
        self.entry_name.grid(row=0, column=1)
        self.entry_name.focus_set()  # 获得焦点
        self.docheck1 = self.entry_name.register(self.usercheck)  # 自带验证功能，usercheck自定义函数
        self.entry_name.config(validate='all', validatecommand=(self.docheck1, '%P'))

        # 文本框 密码
        self.var_usr_pwd = StringVar()
        self.entry_pwd = Entry(self.fr1, textvariable=self.var_usr_pwd, show="*", font=("宋体", 11))
        self.entry_pwd.grid(row=1, column=1)
        self.docheck2 = self.entry_pwd.register(self.passwordcheck)
        self.entry_pwd.config(validate='all', validatecommand=(self.docheck2, '%d', '%S'))
        # 文本框 确认密码
        self.var_usr_repwd = StringVar()
        self.entry_repwd = Entry(self.fr1, textvariable=self.var_usr_repwd, show="*", font=("宋体", 11))
        self.entry_repwd.grid(row=2, column=1)

        self.fr3 = Frame(self.root)
        self.fr3.place(x=252, y=400, width=400, height=210)
        # 登录
        self.root.bind('<Return>', self.reg)  # 绑定回车键
        self.bt_register = Button(self.fr3, text=" 注册 ", command=lambda: self.reg(), font=("楷体", 11))
        self.bt_register.grid(row=1, column=1, pady=5, padx=50)

        self.bt_quit = Button(self.fr3, text=" 退出 ", command=sys.exit, font=("楷体", 11))
        self.bt_quit.grid(row=1, column=2)

        # # 底部标签
        self.fr4 = Frame(self.root)
        self.fr4.pack(side='bottom')

        self.bt_register = Button(self.fr4, text=" 返回登录", relief=FLAT, bg='#f0f0f0', command=self.register_win_close)
        self.bt_register.pack(side='left', anchor='s')
        self.la2 = Label(self.fr4, width=150)
        self.la2.pack()

    def register_win_close(self):
        self.fr1.destroy()
        self.fr2.destroy()
        self.fr3.destroy()
        self.fr4.destroy()  # 登录界面卸载
        self.Login(Register,self.Chat,self.root)  # 密码对，就把主窗体模块的界面加载

    def usercheck(self, what):
        if len(what) > 8:
            self.la2.config(text='用户名不能超过8个字符', fg='red')
            return False
        return True

    def passwordcheck(self, what):
        if len(what) < 8:
            self.la2.config(text='密码长度不能少于8个字符', fg='red')
            return False
        elif not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', what):
            self.la2.config(
                text='密码至少包含一个大、小写字母、数字和特殊字符(@$!%*?&)，长度不能小于8个字符',
                fg='red')
            return False
        else:
            self.la2.config(text='')
            return True

    def reg(self, *args):
        usr_name = self.var_usr_name.get()
        usr_pwd = self.var_usr_pwd.get()
        usr_repwd = self.var_usr_repwd.get()

        if usr_name == '' or usr_pwd == '' or usr_repwd == '':
            messagebox.showwarning(title='提示', message="用户名密码不能为空")
        else:
            # Connect to the database
            conn = sqlite3.connect('yonghu.db')
            cursor = conn.cursor()
            cursor.execute('create table if not exists user(username varchar(20),password varchar(64))')

            cursor.execute('select username, password from user where username=?', (usr_name,))
            existing_user = cursor.fetchone()

            if existing_user:
                # 如果用户已存在，检查密码是否匹配
                stored_pwd = existing_user[1]
                if stored_pwd == usr_pwd:
                    if messagebox.showinfo('提示', '登录成功！'):
                        self.valid_users[usr_name] = usr_pwd
                        self.root.unbind('<Return>')
                        self.register_win_close()
                else:
                    self.logger.warning('密码错误：用户名 - {}'.format(usr_name))
                    messagebox.showerror('提示', '密码错误！')
            else:
                # 如果用户不存在，注册新用户
                if usr_pwd == usr_repwd:
                    # Hash the password using hashlib
                    hashed_pwd = hashlib.sha256(usr_pwd.encode()).hexdigest()
                    # Insert hashed password into the database
                    cursor.execute("insert into user (username, password) values (?, ?)", (usr_name, hashed_pwd))
                    self.logger.info('注册成功：用户名 - {}'.format(usr_name))
                    if messagebox.showinfo('提示', '注册成功！'):
                        self.valid_users[usr_name] = hashed_pwd
                        self.root.unbind('<Return>')
                        self.register_win_close()
                else:
                    self.logger.error('两次输入的密码不一致：用户名 - {}'.format(usr_name))
                    messagebox.showerror('提示', '两次输入的密码不一致！')

            cursor.close()
            conn.commit()
            conn.close()

        return 'break'

