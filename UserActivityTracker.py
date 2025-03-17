import sqlite3
from tabulate import tabulate

#TODO increaseWarnings, decreaseWarnings, checkIfExist

class UserActivityTracker:

    
    def __init__(self) :
        print("[+] Starting connection to database...\n")
        self.conn = sqlite3.connect('useractivitylogs.db')
        self.cursor = self.conn.cursor()
        self.userActivityLog = {
            "IP": "",
            "MAC": "",
            "MANUFACTURER": "",
            "OWNER": "",
            "WARNING": ""
        }
        self.createTable()

    def createTable(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS UserActivityLog (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                IP TEXT,
                MAC TEXT,
                MANUFACTURER TEXT,
                OWNER TEXT,
                WARNING INTEGER,
                UNIQUE(IP,MAC)
            )
        ''')
        self.conn.commit()

    def logEntry(self,ip,mac,manufacturer):
        self.cursor.execute('''
        INSERT OR IGNORE INTO UserActivityLog (ip, mac, manufacturer) 
        VALUES (?, ?, ?)
        ''', (ip, mac, manufacturer))
        self.conn.commit()

        print("[+] Logging a new entry into the database...")
    
    def updateEntry(self,userActivityLog):
        query = 'UPDATE UserActivityLog SET '
        updates = []
        values = []
        ip = userActivityLog["IP"]
        mac = userActivityLog["MAC"]
        manufacturer = userActivityLog["MANUFACTURER"]
        owner = userActivityLog["OWNER"]

        # Build the query dynamically based on provided values
        if ip != "":
            updates.append('IP = ?')
            values.append(ip)
        if manufacturer != "":
            updates.append('MANUFACTURER = ?')
            values.append(manufacturer)
        if owner != "":
            updates.append('MANUFACTURER = ?')
            values.append(owner)

        query += ', '.join(updates) + '  WHERE mac = ?'
        values.extend([mac])

        self.cursor.execute(query, values)
        self.conn.commit()

        print("[+] Updating an entry into the database...")
    
    def showLogs(self):
        print("[+] Fetching logs from databases...\n")

        self.cursor.execute('SELECT * FROM UserActivityLog')
        
        logs = self.cursor.fetchall()
        headers = ['ID', 'IP', 'MAC', 'MANUFACTURER', 'OWNER', 'WARNING']

        print(tabulate(logs, headers=headers, tablefmt='fancy_grid'))



    def closeConnection(self):
        print("\n[+] Closing connection to database...")
        self.conn.close()
    

