#!/usr/bin/python3
# -*- coding: utf-8 -*-
import subprocess, os, random, string, sys, shutil, socket, zipfile, urllib.request, urllib.error, urllib.parse, json, base64
from itertools import cycle
from zipfile import ZipFile
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

rDownloadURL = {"main": "https://github.com/Servextex/Xtream-UI-Main-Ubuntu20.04/releases/download/start/main_xui.zip", "sub": "https://github.com/Servextex/Xtream-UI-Main-Ubuntu20.04/releases/download/start/sub_xui.zip"}
rPackages = ["libcurl4", "libxslt1-dev", "libgeoip-dev", "libonig-dev", "e2fsprogs", "wget", "mcrypt", "nscd", "htop", "zip", "unzip", "mc", "mariadb-server", "libpng16-16", "libzip5", "python3-paramiko", "python-is-python3", "certbot", "python3-certbot-nginx"]
rInstall = {"MAIN": "main", "LB": "sub"}
rUpdate = {"UPDATE": "update"}
rMySQLCnf = base64.b64decode("IyBYdHJlYW0gQ29kZXMKCltjbGllbnRdCnBvcnQgICAgICAgICAgICA9IDMzMDYKCltteXNxbGRfc2FmZV0KbmljZSAgICAgICAgICAgID0gMAoKW215c3FsZF0KdXNlciAgICAgICAgICAgID0gbXlzcWwKcG9ydCAgICAgICAgICAgID0gNzk5OQpiYXNlZGlyICAgICAgICAgPSAvdXNyCmRhdGFkaXIgICAgICAgICA9IC92YXIvbGliL215c3FsCnRtcGRpciAgICAgICAgICA9IC90bXAKbGMtbWVzc2FnZXMtZGlyID0gL3Vzci9zaGFyZS9teXNxbApza2lwLWV4dGVybmFsLWxvY2tpbmcKc2tpcC1uYW1lLXJlc29sdmU9MQoKYmluZC1hZGRyZXNzICAgICAgICAgICAgPSAqCmtleV9idWZmZXJfc2l6ZSA9IDEyOE0KCm15aXNhbV9zb3J0X2J1ZmZlcl9zaXplID0gNE0KbWF4X2FsbG93ZWRfcGFja2V0ICAgICAgPSA2NE0KbXlpc2FtLXJlY292ZXItb3B0aW9ucyA9IEJBQ0tVUAptYXhfbGVuZ3RoX2Zvcl9zb3J0X2RhdGEgPSA4MTkyCnF1ZXJ5X2NhY2hlX2xpbWl0ICAgICAgID0gNE0KcXVlcnlfY2FjaGVfc2l6ZSAgICAgICAgPSAwCnF1ZXJ5X2NhY2hlX3R5cGUJPSAwCgpleHBpcmVfbG9nc19kYXlzICAgICAgICA9IDEwCm1heF9iaW5sb2dfc2l6ZSAgICAgICAgID0gMTAwTQoKbWF4X2Nvbm5lY3Rpb25zICA9IDIwMDAgI3JlY29tbWVuZGVkIGZvciAxNkdCIHJhbSAKYmFja19sb2cgPSA0MDk2Cm9wZW5fZmlsZXNfbGltaXQgPSAxNjM4NAppbm5vZGJfb3Blbl9maWxlcyA9IDE2Mzg0Cm1heF9jb25uZWN0X2Vycm9ycyA9IDMwNzIKdGFibGVfb3Blbl9jYWNoZSA9IDQwOTYKdGFibGVfZGVmaW5pdGlvbl9jYWNoZSA9IDQwOTYKCgp0bXBfdGFibGVfc2l6ZSA9IDFHCm1heF9oZWFwX3RhYmxlX3NpemUgPSAxRwoKaW5ub2RiX2J1ZmZlcl9wb29sX3NpemUgPSAxMkcgI3JlY29tbWVuZGVkIGZvciAxNkdCIHJhbQppbm5vZGJfYnVmZmVyX3Bvb2xfaW5zdGFuY2VzID0gMQppbm5vZGJfcmVhZF9pb190aHJlYWRzID0gNjQKaW5ub2RiX3dyaXRlX2lvX3RocmVhZHMgPSA2NAppbm5vZGJfdGhyZWFkX2NvbmN1cnJlbmN5ID0gMAppbm5vZGJfZmx1c2hfbG9nX2F0X3RyeF9jb21taXQgPSAwCmlubm9kYl9mbHVzaF9tZXRob2QgPSBPX0RJUkVDVApwZXJmb3JtYW5jZV9zY2hlbWEgPSBPTgppbm5vZGItZmlsZS1wZXItdGFibGUgPSAxCmlubm9kYl9pb19jYXBhY2l0eT0yMDAwMAppbm5vZGJfdGFibGVfbG9ja3MgPSAwCmlubm9kYl9sb2NrX3dhaXRfdGltZW91dCA9IDAKaW5ub2RiX2RlYWRsb2NrX2RldGVjdCA9IDAKaW5ub2RiX2xvZ19maWxlX3NpemUgPSA1MTJNCgpzcWwtbW9kZT0iTk9fRU5HSU5FX1NVQlNUSVRVVElPTiIKCltteXNxbGR1bXBdCnF1aWNrCnF1b3RlLW5hbWVzCm1heF9hbGxvd2VkX3BhY2tldCAgICAgID0gMTZNCgpbbXlzcWxdCgpbaXNhbWNoa10Ka2V5X2J1ZmZlcl9zaXplICAgICAgICAgICAgICA9IDE2TQo=")

rVersions = {
    "20.04": "focal"
}

class col:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m' # orange on some systems
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    LIGHT_GRAY = '\033[37m'
    DARK_GRAY = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'

def generate(length=19): return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))

def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def getVersion():
    try: return os.popen("lsb_release -d").read().split(":")[-1].strip()
    except: return ""

def printc(rText, rColour=col.BRIGHT_GREEN, rPadding=0, rLimit=46):
    print("%s ┌─────────────────────────────────────────────────┐ %s" % (rColour, col.ENDC))
    for i in range(rPadding): print("%s │                                                 │ %s" % (rColour, col.ENDC))
    array = [rText[i:i+rLimit] for i in range(0, len(rText), rLimit)]
    for i in array : print("%s │ %s%s%s │ %s" % (rColour, " "*round(23-(len(i)/2)), i, " "*round(46-(22-(len(i)/2))-len(i)), col.ENDC))
    for i in range(rPadding): print("%s │                                                 │ %s" % (rColour, col.ENDC))
    print("%s └─────────────────────────────────────────────────┘ %s" % (rColour, col.ENDC))
    print(" ")

def prepare(rType="MAIN"):
    global rPackages
    if rType != "MAIN": rPackages = rPackages[:-1]
    printc("Preparing Installation")
    if os.path.isfile('/home/xtreamcodes/iptv_xtream_codes/config'):
        shutil.copyfile('/home/xtreamcodes/iptv_xtream_codes/config', '/tmp/config.xtmp')
    if os.path.isfile('/home/xtreamcodes/iptv_xtream_codes/config'):    
        os.system('chattr -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null')
    for rFile in ["/var/lib/dpkg/lock-frontend", "/var/cache/apt/archives/lock", "/var/lib/dpkg/lock"]:
        try: os.remove(rFile)
        except: pass
    printc("Updating Operating System")
    os.system("apt-get update > /dev/null")
    os.system("apt-get -y full-upgrade > /dev/null")
    if rType == "MAIN":
        printc("Install MariaDB 10.5 repository")
        os.system("apt-get install -y software-properties-common > /dev/null")
        os.system("apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8 >/dev/null 2>&1")
        os.system("add-apt-repository 'deb [arch=amd64,arm64,ppc64el] http://mirror.lstn.net/mariadb/repo/10.5/ubuntu focal main'  > /dev/null")
        os.system("apt-get update > /dev/null")
    for rPackage in rPackages:
        printc("Installing %s" % rPackage)
        os.system("apt-get install %s -y > /dev/null" % rPackage)
    printc("Installing pip2 and python2 paramiko")
    os.system("add-apt-repository universe > /dev/null 2>&1 && curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py > /dev/null 2>&1 && python2 get-pip.py > /dev/null 2>&1 && pip2 install paramiko > /dev/null 2>&1")
    os.system("apt-get install -f > /dev/null") # Clean up above
    try:
        subprocess.check_output("getent passwd xtreamcodes > /dev/null".split())
    except:
        # Create User
        printc("Creating user xtreamcodes")
        os.system("adduser --system --shell /bin/false --group --disabled-login xtreamcodes > /dev/null")
    if not os.path.exists("/home/xtreamcodes"): os.mkdir("/home/xtreamcodes")
    return True

def install(rType="MAIN"):
    global rInstall, rDownloadURL
    printc("Descargando software")
    try: rURL = rDownloadURL[rInstall[rType]]
    except:
        printc("¡URL de descarga no válida!", col.BRIGHT_RED)
        return False
    os.system('wget -q -O "/tmp/xtreamcodes.zip" "%s"' % rURL)
    if os.path.exists("/tmp/xtreamcodes.zip"):
        printc("Instalando software")
        # Añadido el parámetro -o para sobrescribir automáticamente sin preguntar
        os.system('unzip -o "/tmp/xtreamcodes.zip" -d "/home/xtreamcodes/" > /dev/null')
        try: os.remove("/tmp/xtreamcodes.zip")
        except: pass
        return True
    printc("¡Error al descargar el archivo de instalación!", col.BRIGHT_RED)
    return False
    
def update(rType="MAIN"):
    if rType == "UPDATE":
        printc("Enter the link of release_xyz.zip file:", col.BRIGHT_RED)
        rlink = input('Example: https://github.com/Servextex/Xtream-UI-Main-Ubuntu20.04/releases/download/start/release_22f.zip\n\nNow enter the link:\n\n')
    else:
        rlink = "https://github.com/Servextex/Xtream-UI-Main-Ubuntu20.04/releases/download/start/release_22f.zip"
        printc("Downloading Software Update")  
    os.system('wget -q -O "/tmp/update.zip" "%s"' % rlink)
    if os.path.exists("/tmp/update.zip"):
        try: is_ok = zipfile.ZipFile("/tmp/update.zip")
        except:
            printc("Invalid link or zip file is corrupted!", col.BRIGHT_RED)
            os.remove("/tmp/update.zip")
            return False
    rURL = rlink
    printc("Installing Admin Panel")
    if os.path.exists("/tmp/update.zip"):
        try: is_ok = zipfile.ZipFile("/tmp/update.zip")
        except:
            printc("Invalid link or zip file is corrupted!", col.BRIGHT_RED)
            os.remove("/tmp/update.zip")
            return False
        printc("Updating Software")
        os.system('chattr -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null && rm -rf /home/xtreamcodes/iptv_xtream_codes/admin > /dev/null && rm -rf /home/xtreamcodes/iptv_xtream_codes/pytools > /dev/null && unzip /tmp/update.zip -d /tmp/update/ > /dev/null && cp -rf /tmp/update/XtreamUI-master/* /home/xtreamcodes/iptv_xtream_codes/ > /dev/null && rm -rf /tmp/update/XtreamUI-master > /dev/null && rm -rf /tmp/update > /dev/null && chown -R xtreamcodes:xtreamcodes /home/xtreamcodes/ > /dev/null && chmod +x /home/xtreamcodes/iptv_xtream_codes/permissions.sh > /dev/null && chattr +i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null')
        if not "sudo chmod 400 /home/xtreamcodes/iptv_xtream_codes/config" in open("/home/xtreamcodes/iptv_xtream_codes/permissions.sh").read(): os.system('echo "#!/bin/bash\nsudo chmod -R 777 /home/xtreamcodes 2>/dev/null\nsudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type f -exec chmod 644 {} \; 2>/dev/null\nsudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type d -exec chmod 755 {} \; 2>/dev/null\nsudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type f -exec chmod 644 {} \; 2>/dev/null\nsudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type d -exec chmod 755 {} \; 2>/dev/null\nsudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx 2>/dev/null\nsudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp 2>/dev/null\nsudo chmod 400 /home/xtreamcodes/iptv_xtream_codes/config 2>/dev/null" > /home/xtreamcodes/iptv_xtream_codes/permissions.sh')
        os.system("/home/xtreamcodes/iptv_xtream_codes/permissions.sh > /dev/null")
        try: os.remove("/tmp/update.zip")
        except: pass
        return True
    printc("Failed to download installation file!", col.BRIGHT_RED)
    return False

def mysql(rUsername, rPassword):
    global rMySQLCnf
    printc("Configuring MySQL")
    rCreate = True
    if os.path.exists("/etc/mysql/my.cnf"):
        if open("/etc/mysql/my.cnf", "r").read(14) == "# Xtream Codes": rCreate = False
    if rCreate:
        shutil.copy("/etc/mysql/my.cnf", "/etc/mysql/my.cnf.xc")
        rFile = open("/etc/mysql/my.cnf", "wb")
        rFile.write(rMySQLCnf)
        rFile.close()
        os.system("systemctl restart mariadb > /dev/null")
    #printc("Enter MySQL Root Password:", col.BRIGHT_RED)
    for i in range(5):
        rMySQLRoot = "" #raw_input("  ")
        print(" ")
        if len(rMySQLRoot) > 0: rExtra = " -p%s" % rMySQLRoot
        else: rExtra = ""
        rDrop = True
        try:
            if rDrop:
                os.system('mysql -u root%s -e "DROP DATABASE IF EXISTS xtream_iptvpro; CREATE DATABASE IF NOT EXISTS xtream_iptvpro;" > /dev/null' % rExtra)
                os.system('mysql -u root%s -e "USE xtream_iptvpro; DROP USER IF EXISTS \'%s\'@\'%%\';" > /dev/null' % (rExtra, rUsername))
                os.system("mysql -u root%s xtream_iptvpro < /home/xtreamcodes/iptv_xtream_codes/database.sql > /dev/null" % rExtra)
                os.system('mysql -u root%s -e "USE xtream_iptvpro; UPDATE settings SET live_streaming_pass = \'%s\', unique_id = \'%s\', crypt_load_balancing = \'%s\';" > /dev/null' % (rExtra, generate(20), generate(10), generate(20)))
                os.system('mysql -u root%s -e "USE xtream_iptvpro; REPLACE INTO streaming_servers (id, server_name, domain_name, server_ip, vpn_ip, ssh_password, ssh_port, diff_time_main, http_broadcast_port, total_clients, system_os, network_interface, latency, status, enable_geoip, geoip_countries, last_check_ago, can_delete, server_hardware, total_services, persistent_connections, rtmp_port, geoip_type, isp_names, isp_type, enable_isp, boost_fpm, http_ports_add, network_guaranteed_speed, https_broadcast_port, https_ports_add, whitelist_ips, watchdog_data, timeshift_only) VALUES (1, \'Main Server\', \'\', \'%s\', \'\', NULL, NULL, 0, 25461, 1000, \'%s\', \'eth0\', 0, 1, 0, \'\', 0, 0, \'{}\', 3, 0, 25462, \'low_priority\', \'\', \'low_priority\', 0, 1, \'\', 1000, 25463, \'\', \'[\"127.0.0.1\",\"\"]\', \'{}\', 0);" > /dev/null' % (rExtra, getIP(), getVersion()))
                os.system('mysql -u root%s -e "USE xtream_iptvpro; REPLACE INTO reg_users (id, username, password, email, member_group_id, verified, status) VALUES (1, \'admin\', \'\$6\$rounds=20000\$xtreamcodes\$XThC5OwfuS0YwS4ahiifzF14vkGbGsFF1w7ETL4sRRC5sOrAWCjWvQJDromZUQoQuwbAXAFdX3h3Cp3vqulpS0\', \'admin@website.com\', 1, 1, 1);" > /dev/null'  % rExtra)
                os.system('mysql -u root%s -e "CREATE USER \'%s\'@\'%%\' IDENTIFIED BY \'%s\'; GRANT ALL PRIVILEGES ON xtream_iptvpro.* TO \'%s\'@\'%%\' WITH GRANT OPTION; GRANT SELECT, LOCK TABLES ON *.* TO \'%s\'@\'%%\';FLUSH PRIVILEGES;" > /dev/null' % (rExtra, rUsername, rPassword, rUsername, rUsername))
                os.system('mysql -u root%s -e "USE xtream_iptvpro; CREATE TABLE IF NOT EXISTS dashboard_statistics (id int(11) NOT NULL AUTO_INCREMENT, type varchar(16) NOT NULL DEFAULT \'\', time int(16) NOT NULL DEFAULT \'0\', count int(16) NOT NULL DEFAULT \'0\', PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=latin1; INSERT INTO dashboard_statistics (type, time, count) VALUES(\'conns\', UNIX_TIMESTAMP(), 0),(\'users\', UNIX_TIMESTAMP(), 0);\" > /dev/null' % rExtra)
            try: os.remove("/home/xtreamcodes/iptv_xtream_codes/database.sql")
            except: pass
            return True
        except: printc("Invalid password! Try again", col.BRIGHT_RED)
    return False

def encrypt(rHost="127.0.0.1", rUsername="user_iptvpro", rPassword="", rDatabase="xtream_iptvpro", rServerID=1, rPort=7999):
    if os.path.isfile('/home/xtreamcodes/iptv_xtream_codes/config'):
        rDecrypt = decrypt()
        rHost = rDecrypt["host"]
        rPassword = rDecrypt["db_pass"]
        rServerID = int(rDecrypt["server_id"])
        rUsername = rDecrypt["db_user"]
        rDatabase = rDecrypt["db_name"]
        rPort = int(rDecrypt["db_port"])
    printc("Encrypting...")
    try: os.remove("/home/xtreamcodes/iptv_xtream_codes/config")
    except: pass

    rf = open('/home/xtreamcodes/iptv_xtream_codes/config', 'wb')
    lestring=''.join(chr(ord(c)^ord(k)) for c,k in zip('{\"host\":\"%s\",\"db_user\":\"%s\",\"db_pass\":\"%s\",\"db_name\":\"%s\",\"server_id\":\"%d\", \"db_port\":\"%d\"}' % (rHost, rUsername, rPassword, rDatabase, rServerID, rPort), cycle('5709650b0d7806074842c6de575025b1')))
    rf.write(base64.b64encode(bytes(lestring, 'ascii')))
    rf.close()


def decrypt():
    rConfigPath = "/home/xtreamcodes/iptv_xtream_codes/config"
    try: return json.loads(''.join(chr(c^ord(k)) for c,k in zip(base64.b64decode(open(rConfigPath, 'rb').read()), cycle('5709650b0d7806074842c6de575025b1'))))
    except: return None

def configure():
    printc("Configuring System")
    if not "/home/xtreamcodes/iptv_xtream_codes/" in open("/etc/fstab").read():
        rFile = open("/etc/fstab", "a")
        rFile.write("tmpfs /home/xtreamcodes/iptv_xtream_codes/streams tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=90% 0 0\ntmpfs /home/xtreamcodes/iptv_xtream_codes/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=2G 0 0")
        rFile.close()
    if not "xtreamcodes" in open("/etc/sudoers").read():
        os.system('echo "xtreamcodes ALL = (root) NOPASSWD: /sbin/iptables, /usr/bin/chattr" >> /etc/sudoers')
    if not os.path.exists("/etc/init.d/xtreamcodes"):
        rFile = open("/etc/init.d/xtreamcodes", "w")
        rFile.write("#! /bin/bash\n/home/xtreamcodes/iptv_xtream_codes/start_services.sh")
        rFile.close()
        os.system("chmod +x /etc/init.d/xtreamcodes > /dev/null")
    try: os.remove("/usr/bin/ffmpeg")
    except: pass
    if not os.path.exists("/home/xtreamcodes/iptv_xtream_codes/tv_archive"): os.mkdir("/home/xtreamcodes/iptv_xtream_codes/tv_archive/")
    os.system("ln -s /home/xtreamcodes/iptv_xtream_codes/bin/ffmpeg /usr/bin/")
    if not os.path.exists("/home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb"): os.system("wget -q https://github.com/Servextex/Xtream-UI-Main-Ubuntu20.04/releases/download/start/GeoLite2.mmdb -O /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb")
    if not os.path.exists("/home/xtreamcodes/iptv_xtream_codes/crons/pid_monitor.php"): os.system("wget -q https://github.com/Servextex/Xtream-UI-Main-Ubuntu20.04/releases/download/start/pid_monitor.php -O /home/xtreamcodes/iptv_xtream_codes/crons/pid_monitor.php")
    os.system("chown xtreamcodes:xtreamcodes -R /home/xtreamcodes > /dev/null")
    os.system("chmod -R 0777 /home/xtreamcodes > /dev/null")
    os.system("chattr -ai /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null")
    os.system("sudo chmod 0777 /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null")
    os.system("sed -i 's|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes 2>/dev/null|g' /home/xtreamcodes/iptv_xtream_codes/start_services.sh")
    os.system("chmod +x /home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null")
    os.system("mount -a")
    os.system("chmod 0700 /home/xtreamcodes/iptv_xtream_codes/config > /dev/null")
    os.system("sed -i 's|echo \"Xtream Codes Reborn\";|header(\"Location: https://www.google.com/\");|g' /home/xtreamcodes/iptv_xtream_codes/wwwdir/index.php")
    if not "api.xtream-codes.com" in open("/etc/hosts").read(): os.system('echo "127.0.0.1    api.xtream-codes.com" >> /etc/hosts')
    if not "downloads.xtream-codes.com" in open("/etc/hosts").read(): os.system('echo "127.0.0.1    downloads.xtream-codes.com" >> /etc/hosts')
    if not "xtream-codes.com" in open("/etc/hosts").read(): os.system('echo "127.0.0.1    xtream-codes.com" >> /etc/hosts')
    if not "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" in open("/etc/crontab").read(): os.system('echo "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" >> /etc/crontab')

def configurePHP():
    printc("Optimizing PHP Configuration")
    phpPath = "/home/xtreamcodes/iptv_xtream_codes/php/etc/php.ini"
    if os.path.exists(phpPath):
        # Optimizar parámetros clave de PHP
        replacements = {
            "max_execution_time = 30": "max_execution_time = 300",
            "memory_limit = 128M": "memory_limit = 512M",
            "post_max_size = 8M": "post_max_size = 100M",
            "upload_max_filesize = 2M": "upload_max_filesize = 100M",
            "default_socket_timeout = 60": "default_socket_timeout = 300"
        }
        
        try:
            content = open(phpPath, "r").read()
            for old, new in replacements.items():
                content = content.replace(old, new)
            
            open(phpPath, "w").write(content)
            printc("PHP configurado exitosamente", col.BRIGHT_GREEN)
        except Exception as e:
            printc("Error al configurar PHP: %s" % str(e), col.BRIGHT_RED)


def testConnectivity():
    printc("Diagnóstico completo del sistema")
    localIP = getIP()
    
    # 1. Verificar que los binarios están presentes y con permisos de ejecución
    binarios = [
        "/home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx",
        "/home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp",
        "/home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm"
    ]
    
    printc("Verificando binarios esenciales:", col.BRIGHT_CYAN)
    for binario in binarios:
        if os.path.exists(binario):
            permisos = oct(os.stat(binario).st_mode)[-3:]
            if permisos == "755" or permisos == "775" or permisos == "777":
                printc(f"  ✔ {os.path.basename(binario)} encontrado y con permisos de ejecución", col.BRIGHT_GREEN)
            else:
                printc(f"  ✘ {os.path.basename(binario)} encontrado pero SIN permisos de ejecución", col.BRIGHT_RED)
                os.system(f"chmod +x {binario}")
                printc(f"    → Permisos corregidos para {os.path.basename(binario)}", col.BRIGHT_GREEN)
        else:
            printc(f"  ✘ {os.path.basename(binario)} NO encontrado. Instalación incompleta", col.BRIGHT_RED)
    
    # 2. Verificar procesos en ejecución
    printc("\nVerificando procesos en ejecución:", col.BRIGHT_CYAN)
    procesos = ["nginx", "php-fpm", "mysql"]
    for proceso in procesos:
        proc_count = int(os.popen(f"ps aux | grep -v grep | grep {proceso} | wc -l").read().strip())
        if proc_count > 0:
            printc(f"  ✔ {proceso}: {proc_count} procesos en ejecución", col.BRIGHT_GREEN)
        else:
            printc(f"  ✘ {proceso}: no se está ejecutando", col.BRIGHT_RED)
    
    # 3. Verificar logs en busca de errores
    printc("\nVerificando archivos de log:", col.BRIGHT_CYAN)
    logs = [
        "/home/xtreamcodes/iptv_xtream_codes/logs/error.log",
        "/home/xtreamcodes/iptv_xtream_codes/logs/admin_error.log",
        "/home/xtreamcodes/iptv_xtream_codes/logs/php_error.log"
    ]
    for log in logs:
        if os.path.exists(log):
            # Mostrar últimas 5 líneas de errores
            tail_errors = os.popen(f"tail -n 5 {log} | grep -i 'error'").read().strip()
            if tail_errors:
                printc(f"  ⚠ {os.path.basename(log)}: Errores encontrados", col.BRIGHT_YELLOW)
                for line in tail_errors.split("\n")[:3]:
                    if line.strip():
                        printc(f"    → {line[:100]}{'...' if len(line) > 100 else ''}", col.BRIGHT_YELLOW)
            else:
                printc(f"  ✔ {os.path.basename(log)}: Sin errores recientes", col.BRIGHT_GREEN)
        else:
            os.system(f"touch {log}")
            printc(f"  ⚠ {os.path.basename(log)}: No existía, se ha creado", col.BRIGHT_YELLOW)
    
    # 4. Prueba de puertos abiertos
    printc("\nVerificando puertos:", col.BRIGHT_CYAN)
    nginxStatus = os.popen("netstat -tuln | grep -E ':(25500)'").read().strip()
    if nginxStatus:
        printc(f"  ✔ Puerto administrativo 25500 abierto", col.BRIGHT_GREEN)
    else:
        printc("  ✘ Puerto administrativo 25500 NO está abierto", col.BRIGHT_RED)
        # Intentar corregir reiniciando nginx
        printc("    → Intentando reiniciar Nginx...", col.BRIGHT_YELLOW)
        os.system("/home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx -s reload")
    
    # 5. Prueba de acceso local al panel admin
    printc("\nProbando acceso al panel admin:", col.BRIGHT_CYAN)
    try:
        testURL = "http://localhost:25500/"
        request = Request(testURL)
        response = urlopen(request, timeout=10)
        printc(f"  ✔ Panel administrativo accesible localmente: Estado {response.getcode()}", col.BRIGHT_GREEN)
    except Exception as e:
        printc(f"  ✘ Error accediendo al panel administrativo: {str(e)}", col.BRIGHT_RED)
        
        # Sugerencias basadas en errores comunes
        if "Connection refused" in str(e):
            printc("    → Recomendación: Verifica que Nginx esté ejecutándose", col.BRIGHT_YELLOW)
            printc("    → Ejecuta: /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx", col.BRIGHT_YELLOW)
        elif "timed out" in str(e):
            printc("    → Recomendación: Posible bloqueo en PHP-FPM", col.BRIGHT_YELLOW)
            printc("    → Ejecuta: ps aux | grep php-fpm | grep -v grep && /home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm --fpm-config /home/xtreamcodes/iptv_xtream_codes/php/etc/php-fpm.conf", col.BRIGHT_YELLOW)
            
    # 6. Instrucciones de reinicio manual
    printc("\nComandos para reinicio manual en caso de problemas:", col.BRIGHT_CYAN)
    printc("  1. Reiniciar todos los servicios:", col.BRIGHT_YELLOW)
    printc("     /home/xtreamcodes/iptv_xtream_codes/start_services.sh", col.WHITE)
    printc("  2. Reiniciar Nginx solamente:", col.BRIGHT_YELLOW)
    printc("     /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx -s stop && /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx", col.WHITE)
    printc("  3. Reiniciar PHP-FPM solamente:", col.BRIGHT_YELLOW)
    printc("     kill -9 $(ps aux | grep php-fpm | grep -v grep | awk '{print $2}') && /home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm --fpm-config /home/xtreamcodes/iptv_xtream_codes/php/etc/php-fpm.conf", col.WHITE)


def start(first=True):
    if first: printc("Iniciando servicios de Xtream Codes")
    else: printc("Reiniciando servicios de Xtream Codes")
    
    # Verificar que los binarios existen y tienen permisos de ejecución
    binarios = {
        "nginx": "/home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx",
        "nginx_rtmp": "/home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp",
        "php-fpm": "/home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm"
    }
    
    for nombre, ruta in binarios.items():
        if os.path.exists(ruta):
            # Asegurar permisos de ejecución
            if not os.access(ruta, os.X_OK):
                os.system(f"chmod +x {ruta}")
                printc(f"Corregidos permisos para {nombre}", col.BRIGHT_YELLOW)
        else:
            printc(f"ERROR: No se encontró binario {nombre} en {ruta}", col.BRIGHT_RED)
    
    # Detener servicios existentes primero
    printc("Deteniendo servicios previos...", col.BRIGHT_CYAN)
    os.system("killall -9 nginx php-fpm 2>/dev/null")
    os.system("kill -9 $(ps aux | grep -v grep | grep 'nginx\|php-fpm' | awk '{print $2}') 2>/dev/null")
    time.sleep(1)
    
    # Verificar directorio de logs
    logs_dir = "/home/xtreamcodes/iptv_xtream_codes/logs"
    if not os.path.exists(logs_dir):
        os.system(f"mkdir -p {logs_dir}")
    
    # Iniciar servicios manualmente para evitar problemas
    printc("Iniciando servicios...")
    try:
        # 1. Iniciar MySQL si no está ejecutándose
        mysql_running = int(os.popen("ps aux | grep mysql | grep -v grep | wc -l").read().strip()) > 0
        if not mysql_running:
            os.system("/etc/init.d/mysql restart > /dev/null 2>&1")
            printc("  → MySQL iniciado", col.BRIGHT_GREEN)
        
        # 2. Iniciar PHP-FPM
        os.system(f"{binarios['php-fpm']} --fpm-config /home/xtreamcodes/iptv_xtream_codes/php/etc/php-fpm.conf > /dev/null 2>&1")
        printc("  → PHP-FPM iniciado", col.BRIGHT_GREEN)
        
        # 3. Iniciar Nginx
        os.system(f"{binarios['nginx']} > /dev/null 2>&1")
        printc("  → Nginx iniciado", col.BRIGHT_GREEN)
        
        # 4. Iniciar Nginx_RTMP
        os.system(f"{binarios['nginx_rtmp']} > /dev/null 2>&1")
        printc("  → Nginx RTMP iniciado", col.BRIGHT_GREEN)
        
    except Exception as e:
        printc(f"Error iniciando servicios: {str(e)}", col.BRIGHT_RED)
        printc("Intentando método alternativo...", col.BRIGHT_YELLOW)
        os.system("/home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null 2>&1")
    
    # Verificar si los servicios están funcionando
    time.sleep(5) # Esperar a que los servicios se inicien
    nginx_running = int(os.popen("ps aux | grep nginx | grep -v grep | wc -l").read().strip()) > 0
    phpfpm_running = int(os.popen("ps aux | grep php-fpm | grep -v grep | wc -l").read().strip()) > 0
    mysql_running = int(os.popen("ps aux | grep mysql | grep -v grep | wc -l").read().strip()) > 0
    
    if nginx_running and phpfpm_running and mysql_running:
        printc("Todos los servicios iniciados correctamente", col.BRIGHT_GREEN)
    else:
        if not nginx_running:
            printc("Servicio Nginx NO iniciado. Intentando solución...", col.BRIGHT_RED)
            os.system(f"{binarios['nginx']} -t > {logs_dir}/nginx_test.log 2>&1") # Probar configuración
            printc(f"Ver log de prueba en {logs_dir}/nginx_test.log", col.BRIGHT_YELLOW)
        if not phpfpm_running: 
            printc("Servicio PHP-FPM NO iniciado. Intentando solución...", col.BRIGHT_RED)
            os.system(f"{binarios['php-fpm']} -t 2> {logs_dir}/php_test.log") # Probar configuración
            printc(f"Ver log de prueba en {logs_dir}/php_test.log", col.BRIGHT_YELLOW)
        if not mysql_running: printc("Servicio MySQL NO iniciado", col.BRIGHT_RED)
    
    # Verificar si el puerto está escuchando
    port_open = len(os.popen("netstat -tuln | grep :25500").read().strip()) > 0
    if port_open:
        printc("Puerto 25500 abierto y listo para conexiones", col.BRIGHT_GREEN)
    else:
        printc("¡Advertencia! El puerto 25500 del panel administrativo no está abierto", col.BRIGHT_RED)
        printc("Verificando logs de error de Nginx...", col.BRIGHT_YELLOW)
        os.system(f"tail -n 20 {logs_dir}/error.log 2>/dev/null || echo 'No hay logs disponibles'")
        
        # Intentar una última vez con reinicio completo
        printc("Intentando un último reinicio de Nginx...", col.BRIGHT_YELLOW)
        os.system(f"{binarios['nginx']} -s stop 2>/dev/null")
        time.sleep(1)
        os.system(f"{binarios['nginx']} 2>/dev/null")
        time.sleep(2)
        
        # Verificar nuevamente
        port_open = len(os.popen("netstat -tuln | grep :25500").read().strip()) > 0
        if port_open:
            printc("Puerto 25500 ahora está abierto y listo", col.BRIGHT_GREEN)
        else:
            printc("¡Error persistente! Puerto 25500 sigue cerrado", col.BRIGHT_RED)

def modifyNginx():
    printc("Modificando Nginx (binarios propios de Xtream UI)")
    rPath = "/home/xtreamcodes/iptv_xtream_codes/nginx/conf/nginx.conf"
    
    # Verificar si el binario de nginx existe
    if not os.path.exists("/home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx"):
        printc("¡Advertencia! No se encuentra el binario de Nginx. La instalación puede estar incompleta.", col.BRIGHT_RED)
        return
    
    # Asegurar permisos de ejecución para el binario de Nginx
    os.system("chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx")
    os.system("chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp")
    
    # Verificar si ya está definida la zona de limitación de solicitudes
    rPrevData = open(rPath, "r").read()
    if not "limit_req_zone" in rPrevData:
        # Añadir zona de limitación al inicio del archivo
        with open(rPath, "r") as f:
            content = f.read()
        with open(rPath, "w") as f:
            f.write("limit_req_zone $binary_remote_addr zone=one:10m rate=5r/s;\n" + content)
        
    # Volver a leer el archivo después de posibles modificaciones
    rPrevData = open(rPath, "r").read()
    if not "listen 25500;" in rPrevData:
        shutil.copy(rPath, "%s.xc" % rPath)
        rData = "}".join(rPrevData.split("}")[:-1]) + """    server {\n        listen 25500;\n        index index.php index.html index.htm;\n        root /home/xtreamcodes/iptv_xtream_codes/admin/;\n        client_max_body_size 100M;\n        client_body_timeout 300s;\n        access_log /home/xtreamcodes/iptv_xtream_codes/logs/admin_access.log;\n        error_log /home/xtreamcodes/iptv_xtream_codes/logs/admin_error.log;\n        \n        # Timeouts optimizados\n        proxy_connect_timeout 600;\n        proxy_send_timeout 600;\n        proxy_read_timeout 600;\n        fastcgi_read_timeout 600;\n\n        location ~ \.php$ {\n\t\t\tlimit_req zone=one burst=10 nodelay;\n            try_files $uri =404;\n\t\t\tfastcgi_index index.php;\n\t\t\tfastcgi_pass php;\n\t\t\tinclude fastcgi_params;\n\t\t\tfastcgi_buffering on;\n\t\t\tfastcgi_buffers 96 32k;\n\t\t\tfastcgi_buffer_size 32k;\n\t\t\tfastcgi_max_temp_file_size 0;\n\t\t\tfastcgi_keep_conn on;\n\t\t\tfastcgi_connect_timeout 300s;\n\t\t\tfastcgi_send_timeout 300s;\n\t\t\tfastcgi_read_timeout 300s;\n\t\t\tfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n\t\t\tfastcgi_param SCRIPT_NAME $fastcgi_script_name;\n        }\n    }\n}"""
        rFile = open(rPath, "w")
        rFile.write(rData)
        rFile.close()
    
    # Verificar archivos de configuración PHP
    phpFpmConfPath = "/home/xtreamcodes/iptv_xtream_codes/php/etc/php-fpm.conf"
    if os.path.exists(phpFpmConfPath):
        printc("Optimizando PHP-FPM para Nginx...", col.BRIGHT_GREEN)
        # Aumentar el número máximo de procesos PHP-FPM
        os.system(f"sed -i 's/max_children = 5/max_children = 30/g' {phpFpmConfPath}")
        os.system(f"sed -i 's/request_terminate_timeout = 300/request_terminate_timeout = 600/g' {phpFpmConfPath}")
    else:
        printc("¡Advertencia! No se encuentra el archivo de configuración PHP-FPM.", col.BRIGHT_YELLOW)

def setupSSL(domain=None):
    """Configurar SSL utilizando Let's Encrypt"""
    if not domain:
        printc("Necesita proporcionar un dominio válido para configurar SSL", col.BRIGHT_RED)
        return False
    
    printc(f"Configurando SSL para el dominio: {domain}", col.BRIGHT_CYAN)
    
    # Modificar nginx para usar el dominio
    nginxAdminPath = "/home/xtreamcodes/iptv_xtream_codes/nginx/conf/nginx.conf"
    
    # Respaldo del archivo de configuración
    shutil.copy(nginxAdminPath, f"{nginxAdminPath}.bak_ssl")
    
    # Leer la configuración actual
    content = open(nginxAdminPath, "r").read()
    
    # Modificar para usar el dominio en puerto 25500
    modified_content = content.replace("listen 25500;", f"listen 25500;\n        server_name {domain};")
    
    with open(nginxAdminPath, "w") as f:
        f.write(modified_content)
    
    # Reiniciar Nginx para aplicar cambios
    os.system("/home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx -s reload")
    
    # Ejecutar certbot para obtener certificado
    try:
        printc("Obteniendo certificado SSL con Let's Encrypt...", col.BRIGHT_GREEN)
        result = os.system(f"certbot --nginx --non-interactive --agree-tos --email admin@{domain} -d {domain} --redirect")
        
        if result == 0:
            printc("¡Certificado SSL instalado correctamente!", col.BRIGHT_GREEN)
            return True
        else:
            printc("Error al obtener certificado SSL. Verifica que el dominio apunte correctamente a este servidor.", col.BRIGHT_RED)
            return False
    except Exception as e:
        printc(f"Error configurando SSL: {str(e)}", col.BRIGHT_RED)
        return False


if __name__ == "__main__":
    try: rVersion = os.popen('lsb_release -sr').read().strip()
    except: rVersion = None
    if not rVersion in rVersions:
        printc("Unsupported Operating System, Works only on Ubuntu Server 20")
        sys.exit(1)
    printc("X-UI 22f Ubuntu %s Installer - Servextex (Mejorado)" % rVersion, col.GREEN, 2)
    print(" ")
    rType = input("  Tipo de instalación [MAIN, LB, UPDATE]: ")
    print(" ")
    if rType.upper() in ["MAIN", "LB"]:
        if rType.upper() == "LB":
            rHost = input("  Dirección IP del servidor principal: ")
            rPassword = input("  Contraseña MySQL: ")
            try: rServerID = int(input("  ID del servidor de balanceo de carga: "))
            except: rServerID = -1
            print(" ")
        else:
            rHost = "127.0.0.1"
            rPassword = generate()
            rServerID = 1
        rUsername = "user_iptvpro"
        rDatabase = "xtream_iptvpro"
        rPort = 7999
        
        # Preguntar si se usará dominio y SSL
        useSSL = input("  ¿Configurar con dominio y SSL? (S/N): ").upper() == "S"
        domain = None
        if useSSL:
            domain = input("  Ingrese el nombre de dominio (ej: panel.sudominio.com): ").strip()
            if not domain:
                printc("Dominio no válido. Continuando sin SSL.", col.BRIGHT_YELLOW)
                useSSL = False
        
        if len(rHost) > 0 and len(rPassword) > 0 and rServerID > -1:
            printc("¿Iniciar instalación? S/N", col.BRIGHT_YELLOW)
            if input("  ").upper() == "S":
                print(" ")
                rRet = prepare(rType.upper())
                if not install(rType.upper()): sys.exit(1)
                if rType.upper() == "MAIN":
                    if not mysql(rUsername, rPassword): sys.exit(1)
                encrypt(rHost, rUsername, rPassword, rDatabase, rServerID, rPort)
                configure()
                if rType.upper() == "MAIN": 
                    modifyNginx()
                    configurePHP() # Optimizar configuración de PHP
                    update(rType.upper())
                start()
                
                # Configurar SSL si se seleccionó
                ssl_success = False
                if useSSL and domain:
                    ssl_success = setupSSL(domain)
                
                # Probar conectividad
                testConnectivity()
                
                printc("¡Instalación completada!", col.GREEN, 2)
                if rType.upper() == "MAIN":
                    printc("Guarde su contraseña MySQL: %s" % rPassword, col.BRIGHT_YELLOW)
                    
                    # URL con protocolo correcto según SSL
                    protocol = "https" if (useSSL and ssl_success) else "http"
                    host = domain if (useSSL and ssl_success) else getIP()
                    printc(f"Panel de administración: {protocol}://{host}:25500", col.BRIGHT_YELLOW)
                    printc("Credenciales por defecto: admin/admin", col.BRIGHT_YELLOW)
                    printc("Credenciales guardadas en el archivo /root/credentials.txt", col.BRIGHT_YELLOW)
                    
                    rFile = open("/root/credentials.txt", "w")
                    rFile.write("Contraseña MySQL: %s\n" % rPassword)
                    rFile.write(f"Panel de administración: {protocol}://{host}:25500\n")
                    rFile.write("Credenciales por defecto: admin/admin\n")
                    if useSSL:
                        rFile.write(f"SSL configurado: {'Sí' if ssl_success else 'No (ver errores)'}\n")
                    rFile.close()
            else: printc("Instalación cancelada", col.BRIGHT_RED)
        else: printc("Entradas no válidas", col.BRIGHT_RED)
    elif rType.upper() == "UPDATE":
        if os.path.exists("/home/xtreamcodes/iptv_xtream_codes/wwwdir/api.php"):
            printc("¿Actualizar panel de administración? S/N?", col.BRIGHT_YELLOW)
            if input("  ").upper() == "S":
                if not update(rType.upper()): sys.exit(1)
                configurePHP() # Optimizar configuración de PHP
                printc("¡Instalación completada!", col.GREEN, 2)
                start()
                testConnectivity() # Probar conexión después de actualizar
            else: printc("¡Instale Xtream Codes Main primero!", col.BRIGHT_RED)
    else: printc("Tipo de instalación no válido", col.BRIGHT_RED)
