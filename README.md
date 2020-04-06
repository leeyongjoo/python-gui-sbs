# python-gui-sbs
💰python으로 구현한 간단한 은행 시스템(Simple Banking System)

## Installation
[pip](https://pip.pypa.io/en/stable/)를 이용하여 라이브러리 설치 *Python Version: 3.8*
```bash
pip install -r requirements.txt
```

## Features
1. tkinter  
2. pycryptodome
3. socket
4. threading

- 하이브리드 보안 통신
    - AES 기반 메시지 암/복호화
    - RSA 기반 키 교환
- 검증을 포함한 Client/Server 간 정보 교환
    - One-way Hash 사용(SHA)
    - Digital Signature
- 메시지 교환
    - Socket을 이용한 Client/Server
    - 각자의 공개키 파일 전송, 메시지 송수신
- GUI 구현

## Demo
![demo sbs](/_examples/python-gui-sbs.gif)

## Screenshot
1. 초기 실행화면
<img src="https://user-images.githubusercontent.com/46367323/78575234-08ed7b00-7866-11ea-8818-9f18e68a5e8f.png" width="700">

2. 서버 연결
<img src="https://user-images.githubusercontent.com/46367323/78575598-8913e080-7866-11ea-9070-9d223711f127.png" width="700">

3. 로그인
<img src="https://user-images.githubusercontent.com/46367323/78575848-ddb75b80-7866-11ea-8da3-dd7e890047eb.png" width="700">

4. 송금
<img src="https://user-images.githubusercontent.com/46367323/78575877-e60f9680-7866-11ea-9cbe-73090098c38d.png" width="700">

5. 로그아웃 후 다른 아이디 로그인
<img src="https://user-images.githubusercontent.com/46367323/78575899-ef006800-7866-11ea-8c04-6ebab7d2e14a.png" width="700">

6. 서버 로그, 로그(암호문)
<img src="https://user-images.githubusercontent.com/46367323/78575929-f6277600-7866-11ea-81d6-2687a147055d.png" width="300">
<img src="https://user-images.githubusercontent.com/46367323/78575966-02133800-7867-11ea-96a2-4622f4c4dc7a.png" width="600"></img>
