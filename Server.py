'''
December 22 2018
Simple Banking System(Server)
LeeYongJoo_201458046
'''
#======================
# imports
#======================
import tkinter as tk
from tkinter import font
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import Menu
from tkinter import messagebox as msg
from threading import Thread
from datetime import datetime
from _modules.PGP_Code import *

from _modules import ToolTip as tt
import socket
import os.path

id_file_name = "./idList"
server_privatekey = './files_server/server_privatekey.txt'
server_publickey = './files_server/server_publickey.txt'
client_publickey = './files_server/client_publickey.txt'
sig_MSG_server = './files_server/sig_MSG_server.txt'

#=========================
program_name = "Simple Bankig System"

HOST = 'localhost'
PORT = 12345
BUFSIZ = 1024
ADDR = (HOST, PORT)

BLOCK_SIZE = 16
num = 1;    # 메시지 순서
#=====================================================
class Server():
    def __init__(self):         # Initializer method
        # Variable
        self.client_id = None
        self.money = 0
        self.server_socket = None
        self.client_socket = None
        self.isConnected = 0;

        self.win = tk.Tk()
        self.win.title(program_name)
        self.create_widgets()
        self.create_thread()

    def encrypt(self, input):
        sig_text = Generate_DigSig_On_Hashed_Text(input, server_privatekey)

        key_ciphertext = Generate_AES_Enc_On_DigSig_Plus_Key(sig_text, client_publickey)  # client_publickey

        output = B64Encoding(key_ciphertext)

        self.insert_log_enc("<Encrypt>\nINPUT >> "+ input + "\nOUTPUT >> " + str(output))
        return output

    def decrypt(self, input):
        key_ciphertext = B64Decoding(input)

        sig_text = Generate_AES_Dec_For_DigSig_Plus_Key(key_ciphertext, server_privatekey)

        output, result = Verify_DigSig_On_Hashed_File(sig_text, server_publickey)

        self.insert_log_enc("<Decrypt> -> Verified!")
        self.insert_log_enc("<Decrypt>\nINPUT >> "+ str(input) + "\nOUTPUT >> " + output)
        return output


    def create_thread(self):
        self.run_thread = Thread(target=self.thread_handler)
        self.run_thread.start()

    def insert_msg(self, msg):
        global num
        tmp = str(num) + ') ' + msg + '\n'
        num+=1
        self.msg.insert(tk.END, tmp)
        self.msg.see(tk.END)
        self.insert_log(msg)

    def insert_log(self, msg):
        now = datetime.now()
        time1 = now.strftime('[%y/%m/%d %H:%M:%S] ')
        self.log.insert(tk.END, time1 + msg + '\n')
        self.log.see(tk.END)

    def insert_log_enc(self, msg):
        now = datetime.now()
        time1 = now.strftime('[%y/%m/%d %H:%M:%S] ')
        self.log_enc.insert(tk.END, time1 + msg + '\n')
        self.log_enc.see(tk.END)


    def _quit(self):
        self.win.quit()
        self.win.destroy()
        exit()

    def check_login(self, id, pw):

        if not os.path.exists(id_file_name):
            f = open(id_file_name, "w")
            f.close()

        result = 0

        with open(id_file_name, 'rb') as file:
            while True:
                data = file.readline().decode()
                if data == '':
                    break

                data = data.split(" ")

                if id == data[0] and pw == data[1]:
                    self.client_id = data[0]
                    self.money = data[2]
                    result = 1

            file.close()
            return result;

    def disconneted(self):
        self.isConnected = 0
        self.c_addr.configure(text='0.0.0.0')
        self.id.configure(text='<None>')
        self.insert_msg('클라이언트 접속 종료')
        self.client_sock.close()
        self.server_socket.close()
        self.client_sock = None
        self.server_socket = None

    def logout(self):
        self.id.configure(text='<None>')
        self.insert_msg(self.client_id + ' 님이 로그아웃하셨습니다')


    # thread_handler ===============================================
    def thread_handler(self):  # 통신 코드
        while True:

            if self.isConnected == 0:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.bind(ADDR)
                self.server_socket.listen(10)
                self.insert_msg('클라이언트의 접속을 기다리는 중...')

                self.client_sock, addr = self.server_socket.accept()
                self.insert_msg('클라이언트 접속 : ' + addr[0])
                self.c_addr.configure(text=addr[0])
                self.isConnected = 1

                PGP_Generate_Key_File(server_privatekey, server_publickey)
                PGP_Server_Send_File('localhost', 6000, server_publickey)    # publickey 파일 송수신
                PGP_Client_Receive_File('localhost', 7000, client_publickey)

            # 0) login
            self.insert_msg('로그인을 기다리는 중...')
            while True:
                login_data = self.decrypt(self.client_sock.recv(BUFSIZ))

                if login_data == 'disconnect':
                    self.disconneted()
                    break


                login_data = login_data.split(" ")
                id, pw = login_data

                if self.check_login(id, pw) == 0:
                    self.client_sock.send(self.encrypt("discorrect"))
                    continue
                else:
                    s = '계좌 잔액 : ' + str(self.money) + '원'
                    self.client_sock.send(self.encrypt(s))
                    self.insert_msg(id + ' 님이 로그인하셨습니다')
                    self.id.configure(text=id)
                    break

            if self.isConnected == 0:
                continue

            # 1) communicate
            while True:
                data = self.decrypt(self.client_sock.recv(BUFSIZ))

                if data == 'logout':
                    self.logout()
                    break
                elif data == 'disconnect':
                    self.disconneted()
                    break
                else:
                    data = data.split(" ")

                    count = 0
                    with open(id_file_name, 'rb') as file:
                        while True:
                            content = file.readline().decode()
                            if content == '':
                                break
                            content = content.split(" ")

                            if data[0] == content[0]:
                                count+=1
                        file.close()

                    if count == 0:
                        self.client_sock.send(self.encrypt('id_error'))
                        continue

                    #============
                    tmp = ''
                    with open(id_file_name, 'rb') as file:
                        while True:
                            content = file.readline().decode()
                            if content == '':
                                break
                            content = content.split(" ")

                            if self.client_id == content[0]:
                                if  int(data[1]) > int(content[2]) and int(data[1]) > 0:
                                    self.client_sock.send(self.encrypt('money_error'))
                                    break
                                else:
                                    content[2] = str(int(content[2]) - int(data[1]))
                                    self.client_sock.send(self.encrypt(str(content[2])))
                                    self.insert_msg(data[0] + ' 님에게 ' + data[1] + '원 송금했습니다')
                                    isFind = 1
                            elif data[0] == content[0]:
                                content[2] = str(int(content[2]) + int(data[1]))

                            for a in range(3):
                                tmp += content[a]
                                tmp += " "

                            tmp += "\r\n"
                        file.close()

                        with open(id_file_name, 'wb') as file:
                            file.write(tmp.encode())
                            file.close()

    #####################################################################################
    def create_widgets(self):
        font1 = font.Font(family="맑은 고딕", size=11)

        # Tabs ------------------------------------------
        tabControl = ttk.Notebook(self.win)

        self.tab1 = ttk.Frame(tabControl)
        tabControl.add(self.tab1, text='Main')
        self.tab2 = ttk.Frame(tabControl)
        tabControl.add(self.tab2, text='Log')
        self.tab3 = ttk.Frame(tabControl)
        tabControl.add(self.tab3, text='Log(Encrypt Text)')

        tabControl.pack(expand=1, fill="both")


        # Server ------------------------------------------
        self.mighty = ttk.LabelFrame(self.tab1, text=' 서버 화면 ')
        self.mighty.grid(column=0, row=0, padx=8, pady=4)

        ttk.Label(self.mighty, text="서버 주소", anchor='e', font=font1).grid(column=0, row=0)
        self.s_addr = ttk.Label(self.mighty, text=HOST, width=12, anchor='center', font=font1)
        self.s_addr.grid(column=1, row=0)

        ttk.Label(self.mighty, text="포트번호", font=font1).grid(column=0, row=1)
        self.port = ttk.Label(self.mighty, text=PORT, width=12, anchor='center', font=font1)
        self.port.grid(column=1, row=1)

        ttk.Label(self.mighty, text="클라이언트 주소", anchor='e', font=font1).grid(column=2, row=0)
        self.c_addr = ttk.Label(self.mighty, text="0.0.0.0", width = 12, anchor='center', font=font1)
        self.c_addr.grid(column=3, row=0)

        ttk.Label(self.mighty, text="아이디", font=font1).grid(column=2, row=1)
        self.id = ttk.Label(self.mighty, text="<None>", width=12, anchor='center', font=font1)
        self.id.grid(column=3, row=1)

        for child in self.mighty.winfo_children():
            child.grid_configure(padx=4, pady=2)


        # Message ------------------------------------------
        self.mighty2 = ttk.LabelFrame(self.tab1, text=' 메세지 창 ')
        self.mighty2.grid(column=0, row=4, padx=8, pady=4)

        scrol_w = 60; scrol_h = 10
        self.msg = scrolledtext.ScrolledText(self.mighty2, width=scrol_w, height=scrol_h, wrap=tk.WORD, font=font1, insertontime=0)
        self.msg.grid(column=0, row=0, sticky='WE', columnspan=3)

        for child in self.mighty2.winfo_children():
            child.grid_configure(padx=4, pady=2)


        # Log ------------------------------------------

        self.mighty3 = ttk.LabelFrame(self.tab2, text=' 서버 로그 창 ')
        self.mighty3.grid(column=0, row=4, padx=8, pady=4)

        scrol_h = 15
        self.log = scrolledtext.ScrolledText(self.mighty3, width=scrol_w, height=scrol_h, wrap=tk.WORD, font=font1, insertontime=0)
        self.log.grid(column=0, row=0, sticky='WE', columnspan=3)

        for child in self.mighty3.winfo_children():
            child.grid_configure(padx=4, pady=2)


        # Log(encrypt) ---------------------------------
        self.mighty4 = ttk.LabelFrame(self.tab3, text=' 서버 로그 창 (암호문) ')
        self.mighty4.grid(column=0, row=4, padx=8, pady=4)

        scrol_h = 15
        self.log_enc = scrolledtext.ScrolledText(self.mighty4, width=scrol_w, height=scrol_h, wrap=tk.WORD, font=font1,
                                             insertontime=0)
        self.log_enc.grid(column=0, row=0, sticky='WE', columnspan=3)

        for child in self.mighty4.winfo_children():
            child.grid_configure(padx=4, pady=2)

        #=====================================================================================

        menu_bar = Menu(self.win)
        self.win.config(menu=menu_bar)

        file_menu = Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="종료", command=self._quit)
        menu_bar.add_cascade(label="프로그램", menu=file_menu)

        def _msgBox():
            msg.showinfo("Simple Banking System", "간단한 인터넷 뱅킹 시스템입니다.")

        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="정보", command=_msgBox)   # display messagebox when clicked
        menu_bar.add_cascade(label="도움말", menu=help_menu)

        self.win.iconbitmap('bank.ico')


        # Add Tooltips -----------------------------------------------------
        tt.create_ToolTip(self.msg, '정보를 출력합니다')
        tt.create_ToolTip(self.log, '로그 정보를 출력합니다')
        tt.create_ToolTip(self.log_enc, '송수신한 암호문을 출력합니다')

#======================
# Start GUI
#======================
server = Server()
server.win.mainloop()