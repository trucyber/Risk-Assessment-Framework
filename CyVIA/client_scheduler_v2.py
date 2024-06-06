'''
Client side Schedular v2.0

1. Daily Scans (new processes, applications, vulnerarbilities)

'''

import schedule, time, os, nmap, re
from threading import Thread

def scan_processes(): # Scan for new processes
    t1 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t1)
    print('\n** Starting process scanner at', current_time)
    os.system('python process_scanner_v2.py') # Replace python with python3 and file name where needed.

def scan_apps_and_ports():
    t2 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t2)
    print('\n** Starting application, port, and vulnerability scanner at', current_time)
    os.system('python agent_windows_v2.py') # Replace python with python3 and file name where needed.
    
def run_every_hour_task(): 
    t2 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t2)
    print('\n** Starting hourly task at', current_time) 

def run_daily_at_specific_time_task(): # okay
    t3 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t3)
    print('\n** Starting daily task at', current_time) 

def run_n_to_n_minutes_task(): # okay
    t4 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t4)
    print('\n** Starting every n to n minutes task at', current_time)

def run_every_monday_task():
    t5 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t5)
    print('\n** Starting every monday task at', current_time)

def run_every_tuesday_at_time_task():
    t6 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t6)
    print('\n** Starting every tuesday task at', current_time)


t = time.localtime()
current_time = time.strftime("%H:%M:%S", t)
print('\nClient scheduler started at', current_time)

# Schedules - Every n minutes
schedule.every(1).minutes.do(scan_processes) # Scan for new processes
schedule.every(3).minutes.do(scan_apps_and_ports) # Scan for new applications and open ports


# Every hour 
# schedule.every().hour.do(run_every_hour_task) 
  
# Daily at specific time 
# schedule.every().day.at("16:32").do(run_daily_at_specific_time_task) 

# After every n to n mins in between run work() 
# schedule.every(2).to(3).minutes.do(run_n_to_n_minutes_task) 
  
# Every monday 
# schedule.every().monday.do(run_every_monday_task) 
  
# Every tuesday at 18:00
# schedule.every().tuesday.at("18:00").do(run_every_tuesday_at_time_task) 
  
# Run forever 
while True: 
    # Checks whether a scheduled task is pending to run or not 
    schedule.run_pending() 
    time.sleep(1) 