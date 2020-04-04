'''
December 22 2018
Simple Banking System(Client)
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
from tkinter import messagebox as msgbox
from time import  sleep
from threading import Thread
from _modules.PGP_Code import *

from _modules import ToolTip as tt
import socket

client_privatekey = './files_client/client_privatekey.txt'
client_publickey = './files_client/client_publickey.txt'
server_publickey = './files_client/server_publickey.txt'
sig_MSG_client = './files_client/sig_MSG_client.txt'

#=========================
program_name = "Simple Bankig System"

HOST = '127.0.0.1'
PORT = 12345
BUFSIZ = 1024
#=====================================================
class Client():
    def __init__(self):         # Initializer method
        self.win = tk.Tk()

        # Variable
        self.client_sock = None
        self.num = 1
        self.isConnect = 0
        self.isLogin = 0
        self.money = None

        self.win.title(program_name)
        self.create_widgets()

    def encrypt(self, input):

        sig_text = Generate_DigSig_On_Hashed_Text(input, client_privatekey)

        key_ciphertext = Generate_AES_Enc_On_DigSig_Plus_Key(sig_text, server_publickey)

        output = B64Encoding(key_ciphertext)

        return output

    def decrypt(self, input):

        key_ciphertext = B64Decoding(input)

        sig_text = Generate_AES_Dec_For_DigSig_Plus_Key(key_ciphertext, client_privatekey)

        output, result = Verify_DigSig_On_Hashed_File(sig_text, server_publickey)

        return output


    def click_connect(self):
        self.run_thread = Thread(target=self.thread_connector())
        self.run_thread.start()


    def click_login(self):
        if self.isConnect == 0:
            msgbox.showinfo(program_name, '서버와 연결해주세요!')
            return;

        if self.isLogin == 1:
            self.run_thread = Thread(target=self.thread_logout())
            self.run_thread.start()
            self.logout()
            self.connect.configure(state='abled')
            return;

        if self.id_entered.get() == "":
            msgbox.showinfo(program_name, '아이디를 입력해주세요!')
        elif self.pw_entered.get() == "":
            msgbox.showinfo(program_name, '비밀번호를 입력해주세요!')
        else:
            for c in self.id_entered.get():
                if c == " ":
                    msgbox.showinfo(program_name, '아이디를 빈칸 없이 입력해주세요!')
                    return;
            for c in self.pw_entered.get():
                if c == " ":
                    msgbox.showinfo(program_name, '비밀번호를 빈칸 없이 입력해주세요!')
                    return;

            self.run_thread = Thread(target=self.thread_login())
            self.run_thread.start()

            if self.isLogin == 1:
                self.connect.configure(state='disabled')
                self.action.configure(text='로그아웃')

    def click_send(self):
        self.run_progressbar()
        self.run_thread = Thread(target=self.thread_communicator())
        self.run_thread.start()

    def run_progressbar(self):
        self.progress_bar["maximum"] = 100
        for i in range(101):
            sleep(0.001)
            self.progress_bar["value"] = i
            self.progress_bar.update()
        self.progress_bar["value"] = 0
        return 1;

    def insert_msg(self, msg):
        tmp = str(self.num) + ') ' + msg + '\n'
        self.num+=1
        self.msg.insert(tk.END, tmp)
        self.msg.see(tk.END)

    def _quit(self):
        self.win.quit()
        self.win.destroy()
        exit()

    def connected(self):
        self.connect.configure(text='연결 종료')
        self.id_entered.configure(state='abled')
        self.pw_entered.configure(state='abled')
        self.insert_msg(HOST + ' 서버 접속!')
        self.isConnect = 1

    def disconnected(self):
        self.connect.configure(text='서버 연결')
        self.id_entered.configure(state='disabled')
        self.pw_entered.configure(state='disabled')
        self.insert_msg(HOST + ' 서버 접속종료')
        self.client_sock.close()
        self.client_sock = None
        self.isConnect = 0

    def logout(self):
        self.id_entered.configure(state='abled')
        self.id_entered.delete(0, len(self.id.get()))
        self.pw_entered.configure(state='abled')
        self.pw_entered.delete(0, len(self.pw.get()))
        self.recv_id_entered.delete(0, len(self.recv_id.get()))
        self.send_money_entered.delete(0, len(self.send_money.get()))
        self.action.configure(text='로그인')
        self.insert_msg('로그아웃하셨습니다!')
        self.isLogin = 0


    # thread_handler ==================
    def thread_connector(self):  # 서버와 연결
        if self.isConnect == 1:
            self.client_sock.send(self.encrypt('disconnect'))
            self.disconnected()
            return;

        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_addr = (HOST, int(PORT))

        try:
            self.client_sock.connect(sock_addr)
        except:
            self.insert_msg(HOST + ' 서버 접속 실패')
            return;
        finally:
            PGP_Generate_Key_File(client_privatekey, client_publickey)
            PGP_Client_Receive_File('localhost', 6000, server_publickey)    # publickey 파일 송수신
            PGP_Server_Send_File('localhost', 7000, client_publickey)

        self.connected()

    def thread_login(self):  # 로그인
        # 0) login
        c_id = self.id_entered.get()
        c_pw = self.pw_entered.get()

        id_pw = c_id + ' ' + c_pw

        self.client_sock.send(self.encrypt(id_pw))

        data = self.decrypt(self.client_sock.recv(BUFSIZ))

        if data == 'discorrect':
            msgbox.showinfo(program_name, '아이디 또는 비밀번호가 다릅니다')
        else:
            self.insert_msg(c_id + ' 님 반갑습니다!')
            self.isLogin = 1
            self.insert_msg(data)
            self.id_entered.configure(state='disabled')
            self.pw_entered.configure(state='disabled')

    def thread_logout(self):  # 로그아웃
        self.client_sock.send(self.encrypt('logout'))

    def thread_communicator(self):  # 서버와 통신
        recv_id = self.recv_id.get()
        send_money = self.send_money.get()

        if self.recv_id_entered.get() == self.id_entered.get():
            msgbox.showinfo(program_name, '자신의 아이디를 제외하고 입력해주세요!')
            return;
        elif self.recv_id_entered.get() == "":
            msgbox.showinfo(program_name, '받는 사람의 아이디를 입력해주세요!')
            return;
        elif self.send_money_entered.get() == "":
            msgbox.showinfo(program_name, '보낼 금액을 입력해주세요!')
            return;
        elif not self.send_money_entered.get().isdigit():
            msgbox.showinfo(program_name, '보낼 금액을 다시 입력해주세요!')
            return;
        elif int(self.send_money_entered.get()) <= 0:
            msgbox.showinfo(program_name, '보낼 금액이 0원보다 커야합니다!')
            return;
        else:
            for c in self.recv_id_entered.get():
                if c == " ":
                    msgbox.showinfo(program_name, '아이디를 빈칸 없이 입력해주세요!')
                    return;
            for c in self.send_money_entered.get():
                if c == " ":
                    msgbox.showinfo(program_name, '보낼 금액을 빈칸 없이 입력해주세요!')
                    return;

        msg = recv_id + " " + send_money
        self.client_sock.send(self.encrypt(msg))

        result = self.decrypt(self.client_sock.recv(BUFSIZ))

        if result == 'id_error':
            self.insert_msg('해당 아이디가 존재하지 않습니다')
        elif result == 'money_error':
            self.insert_msg('금액이 너무 적거나 많습니다')
        elif result == 'discorrect':
            self.insert_msg('로그인을 먼저 해주세요')
        else:
            self.insert_msg(recv_id + ' 님에게 송금완료, 잔액 : ' + result + '원')

    #####################################################################################
    def create_widgets(self):
        font1 = font.Font(family="맑은 고딕", size=11)

        # Server ------------------------------------------
        self.mighty = ttk.LabelFrame(self.win, text=' 클라이언트 화면 ')
        self.mighty.grid(column=0, row=0, padx=8, pady=4)

        ttk.Label(self.mighty, text="아이디", font=font1).grid(column=0, row=0)
        self.id = tk.StringVar()
        self.id_entered = ttk.Entry(self.mighty, width=13, textvariable=self.id, font=font1, state='disabled')
        self.id_entered.grid(column=0, row=1, sticky='W')

        ttk.Label(self.mighty, text="비밀번호", font=font1).grid(column=1, row=0)
        self.pw = tk.StringVar()
        self.pw_entered = ttk.Entry(self.mighty, width=13, textvariable=self.pw, show='*', font=font1, state='disabled')
        self.pw_entered.grid(column=1, row=1, sticky='W')

        self.action = ttk.Button(self.mighty, text="로그인", command=self.click_login)
        self.action.grid(column=2, row=1)

        self.connect = ttk.Button(self.mighty, text="서버 연결", command=self.click_connect)
        self.connect.grid(column=2, row=0)

        for child in self.mighty.winfo_children():
            child.grid_configure(padx=4, pady=2)


        # Message ------------------------------------------
        self.mighty2 = ttk.LabelFrame(self.win, text=' 메세지 창 ')
        self.mighty2.grid(column=0, row=4, padx=8, pady=4)

        scrol_w = 38; scrol_h = 10
        self.msg = scrolledtext.ScrolledText(self.mighty2, width=scrol_w, height=scrol_h, wrap=tk.WORD, font=font1, insertontime=0)
        self.msg.grid(column=0, row=0, sticky='WE', columnspan=3)

        for child in self.mighty2.winfo_children():
            child.grid_configure(padx=4, pady=2)


        # Transfer ------------------------------------------
        self.mighty3 = ttk.LabelFrame(self.win, text=' 계좌 이체 ')
        self.mighty3.grid(column=0, row=9, padx=8, pady=4)

        ttk.Label(self.mighty3, text="받는사람 ID", font=font1).grid(column=0, row=0)
        self.recv_id = tk.StringVar()
        self.recv_id_entered = ttk.Entry(self.mighty3, width=15, textvariable=self.recv_id, font=font1)
        self.recv_id_entered.grid(column=1, row=0, sticky='W')

        ttk.Label(self.mighty3, text="이체할 금액", font=font1).grid(column=0, row=1)
        self.send_money = tk.StringVar()
        self.send_money_entered = ttk.Entry(self.mighty3, width=15, textvariable=self.send_money, font=font1)
        self.send_money_entered.grid(column=1, row=1, sticky='W')

        self.send_button = ttk.Button(self.mighty3, text="송금", command=self.click_send)
        self.send_button.grid(column=2, row=1)

        self.progress_bar = ttk.Progressbar(self.mighty3, orient='horizontal', length=325, mode='determinate')
        self.progress_bar.grid(column=0, columnspan=3, row=2, pady=2)

        for child in self.mighty3.winfo_children():
            child.grid_configure(padx=4, pady=2)
        #=====================================================================================

        menu_bar = Menu(self.win)
        self.win.config(menu=menu_bar)

        file_menu = Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="종료", command=self._quit)
        menu_bar.add_cascade(label="프로그램", menu=file_menu)

        def _msgBox():
            msgbox.showinfo("Simple Banking System", "간단한 인터넷 뱅킹 시스템입니다.")

        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="정보", command=_msgBox)
        menu_bar.add_cascade(label="도움말", menu=help_menu)

        self.win.iconbitmap('bank.ico')

        self.id_entered.focus()


        # Add Tooltips -----------------------------------------------------
        tt.create_ToolTip(self.id_entered, '아이디를 입력해주세요')
        tt.create_ToolTip(self.pw_entered, '비밀번호를 입력해주세요')
        tt.create_ToolTip(self.msg, '서버로부터 받은 정보를 출력합니다')
        tt.create_ToolTip(self.recv_id_entered, '받는 사람의 아아디를 입력해주세요')
        tt.create_ToolTip(self.send_money_entered, '보낼 금액을 입력해주세요')
        tt.create_ToolTip(self.send_button, '버튼을 누르면 송금합니다')
        tt.create_ToolTip(self.progress_bar, '진행상태를 표시합니다')

#======================
# Start GUI
#======================
client = Client()
client.win.mainloop()