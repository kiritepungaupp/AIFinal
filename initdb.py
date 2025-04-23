import sqlite3
from urllib.parse import urlparse
import socket

class URLdb:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = sqlite3.connect(self.db_file)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._initialize_database()

    def _initialize_database(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS confirmed_ip (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            safe INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction REAL NOT NULL,
            feeback INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        self.conn.commit()
        
    def close(self):
        self.conn.commit()
        self.conn.close()

    def check_ip_db(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        domain = urlparse(url).hostname
        ip = socket.gethostbyname_ex(domain)[2] if domain else None
        if type(ip) == list:
            ip = ip[0]
        result = self.conn.execute("SELECT * FROM confirmed_ip WHERE ip = ?",(ip,)).fetchone()
        print(ip)
        if result:
            return result['safe']
        else:
            return -1
    
    def record_feedback(self,url,prediction,feedback):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO user_feedback (url, prediction, feeback)
            VALUES (?, ?, ?)
        """, (url, prediction, feedback))
        self.conn.commit()
        return 'Feedback Recorded'
    
    def record_results(self,url,prediction):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO test_results (url, prediction)
            VALUES (?, ?)
        """, (url, prediction))
        self.conn.commit()
        return 'Result Recorded'

    def add_ipconfirm(self,ip,status):
        inserts = 1
        addip = ip
        if type(ip) == list:
            inserts = len(ip)
        cursor = self.conn.cursor()
        
        for x in range(inserts):
            if inserts > 1:
                addip = ip[x]
            cursor.execute("""
                INSERT INTO confirmed_ip (ip, safe)
                VALUES (?, ?)
            """, (addip, status))
        self.conn.commit()
        return 'IP Recorded'
        
def getip(url):
    result = []
    for x in url:
        try:
            print(x)
            if not x.startswith(('http://', 'https://')):
                x = 'http://' + x
            domain = urlparse(x).hostname
            print(domain)
            ip = socket.gethostbyname_ex(domain)[2] if domain else None
            if ip:
                print(ip)
                result.append(ip)
        except:
            continue
    res_flat = [item for sublist in result for item in sublist]
    return res_flat


if __name__ == "__main__":
    Database = URLdb('URL.db')
    #print(Database.check_ip_db('https://www.youtube.com/watch?v=8z07gs6D9E8'))

#     safe_domains = [
#     "www.google.com", "www.bing.com", "www.yahoo.com", "www.duckduckgo.com", "www.wikipedia.org",
#     "www.facebook.com", "www.twitter.com", "www.instagram.com", "www.linkedin.com", "www.snapchat.com",
#     "www.youtube.com", "www.vimeo.com", "www.dailymotion.com", "www.netflix.com", "www.hulu.com",
#     "www.bbc.com", "www.cnn.com", "www.nytimes.com", "www.theguardian.com", "www.forbes.com",
#     "www.amazon.com", "www.ebay.com", "www.walmart.com", "www.bestbuy.com", "www.aliexpress.com",
#     "www.paypal.com", "www.chase.com", "www.wellsfargo.com", "www.visa.com", "www.mastercard.com",
#     "www.khanacademy.org", "www.coursera.org", "www.edx.org", "www.udemy.com", "www.mit.edu",
#     "www.spotify.com", "www.soundcloud.com", "www.pandora.com", "www.disneyplus.com", "www.primevideo.com",
#     "www.microsoft.com", "www.apple.com", "www.adobe.com", "www.github.com", "www.stackoverflow.com",
#     "www.webmd.com", "www.mayoclinic.org", "www.cdc.gov", "www.who.int", "www.healthline.com",
#     "www.reddit.com", "www.quora.com", "www.tumblr.com", "www.pinterest.com", "www.tiktok.com",
#     "www.dropbox.com", "www.box.com", "www.icloud.com", "www.drive.google.com", "www.onedrive.com",
#     "www.slack.com", "www.zoom.us", "www.skype.com", "www.teams.microsoft.com", "www.discord.com",
#     "www.tripadvisor.com", "www.booking.com", "www.airbnb.com", "www.expedia.com", "www.hotels.com",
#     "www.uber.com", "www.lyft.com", "www.maps.google.com", "www.waze.com", "www.here.com",
#     "www.mozilla.org", "www.apache.org", "www.nginx.com", "www.mysql.com", "www.postgresql.org",
#     "www.ubuntu.com", "www.debian.org", "www.fedora.org", "www.archlinux.org", "www.gentoo.org",
#     "www.cloudflare.com", "www.akamai.com", "www.fastly.com", "www.verisign.com", "www.letsencrypt.org",
#     "www.openai.com", "www.tensorflow.org", "www.pytorch.org", "www.kaggle.com", "www.scikit-learn.org",
#     "www.nasa.gov", "www.noaa.gov", "www.esa.int", "www.jaxa.jp", "www.isro.gov.in"
# ]


    # iplist = getip(safe_domains)

    # Database.add_ipconfirm(iplist,1)
    print(getip(['https://www.google.com/search?q=samsung+galaxy&sca_esv=92dcb7bc0db55c59&sxsrf=ADLYWIIbdexL6oVCPmFdrhJmrnwJbra0DQ%3A1733706305655&source=hp&ei=QUJWZ7XKJa2OseMPrZ74SA&iflsig=AL9hbdgAAAAAZ1ZQUUXr_lI9i2689LMhR9ptJXeolMqt&ved=0ahUKEwj17vajv5mKAxUtR2wGHS0PHgkQ4dUDCB0&oq=sa&gs_lp=Egdnd3Mtd2l6GgIYAyICc2EqAggEMgoQIxiABBgnGIoFMgQQIxgnMgQQIxgnMg4QLhiABBixAxjRAxjHATILEAAYgAQYsQMYiwMyCBAAGIAEGLEDMgsQABiABBixAxiLAzIREC4YgAQYsQMYxwEYigUYrwEyCxAAGIAEGLEDGIMBMggQLhiABBixA0iOEFBxWIABcAF4AJABAJgBUaABogGqAQEyuAEByAEA-AEBmAIDoAKuAagCCsICBxAjGCcY6gLCAg4QABiABBixAxiDARiLA8ICERAuGIAEGLEDGNEDGIMBGMcBwgIOEC4YgAQYsQMYgwEYigXCAg4QABiABBixAxiDARiKBZgDCPEFcuC5KM_ZCHKSBwEzoAeEHQ&sclient=gws-wiz']))
    print(Database.check_ip_db('https://www.google.com/search?q=samsung+galaxy&sca_esv=92dcb7bc0db55c59&sxsrf=ADLYWIIbdexL6oVCPmFdrhJmrnwJbra0DQ%3A1733706305655&source=hp&ei=QUJWZ7XKJa2OseMPrZ74SA&iflsig=AL9hbdgAAAAAZ1ZQUUXr_lI9i2689LMhR9ptJXeolMqt&ved=0ahUKEwj17vajv5mKAxUtR2wGHS0PHgkQ4dUDCB0&oq=sa&gs_lp=Egdnd3Mtd2l6GgIYAyICc2EqAggEMgoQIxiABBgnGIoFMgQQIxgnMgQQIxgnMg4QLhiABBixAxjRAxjHATILEAAYgAQYsQMYiwMyCBAAGIAEGLEDMgsQABiABBixAxiLAzIREC4YgAQYsQMYxwEYigUYrwEyCxAAGIAEGLEDGIMBMggQLhiABBixA0iOEFBxWIABcAF4AJABAJgBUaABogGqAQEyuAEByAEA-AEBmAIDoAKuAagCCsICBxAjGCcY6gLCAg4QABiABBixAxiDARiLA8ICERAuGIAEGLEDGNEDGIMBGMcBwgIOEC4YgAQYsQMYgwEYigXCAg4QABiABBixAxiDARiKBZgDCPEFcuC5KM_ZCHKSBwEzoAeEHQ&sclient=gws-wiz'))

    