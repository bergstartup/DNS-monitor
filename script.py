"""
Main func init following
1.Controller [Thread 1]
2.Dns sniffer [Thread 2]

For communication among modules
1.Global variables
2.Common queue

Following are global variables
1.File_changed
2.Mailed
3.Filename
4.File_pointer
5.File_size_limit
6.SMTP
7.SMTP_port
8.SMTP_user
9.SMTP_password
10.Email
11.debug
-------------------------------
Functionalities of each module

Controller:
Gets input from event_queue and calls the respective function [write_to_file,mailer,get_new_filename] in
serializing manner.

Dns sniffer:
Sniff dns packets and get the URL to the event_queue
----------------------------------

----------------------------------
Event queue

All modules communicate through event queue. They append their output to the event queue. The Controller
module pop from event queue and execute the corresponding function.

event queus's element format
<event_id,Message>

event_module_id is used to identify the corresponding function to execute
Message is passed as the parameter to the function.

event_id and respective functions to call
0->write_to_file(message)
1->get_new_filename()
2->mailer_handler(message)
----------------------------------

"""


"""
IMPORTS
"""
#Scapy for DNS packet sniffing
from scapy.all import DNSQR,sniff
#OS for stat and listdir
from os import stat,listdir,mkdir
#Thread
import threading
#For email
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

"""
GLOBAL VARIABLES DECLARATION
"""
File_changed=True
Mailed=True
Filename=None
File_size_limit=None
File_pointer=None
debug=True
SMTP=None
SMTP_port=None
SMTP_user=None
SMTP_password=None
Email=None



"""
FUNCTION DEFINITION
"""
def get_latest_filename():
    logs=listdir("logs/")
    nums=[]
    for log in logs:
        nums.append(int(log.split(".")[0].split("_")[1]))
    latest_num=sorted(nums)[-1]
    return "log_"+str(latest_num)+".log"


def init_global_variables():
    #Self explantory
    global Filename
    try:
        logs=listdir("logs/")
        logs.sort()
    except:
        mkdir("logs")
        logs=[]

    if len(logs)==0:
        name="logs_1.log"
    else:
        name=get_latest_filename()
    Filename=name

    global File_pointer
    File_pointer=open("logs/"+Filename,"a")

    if debug:
        print("Filename :",Filename)

    cfg=open("config.cfg","r")
    line=cfg.readline()
    global File_size_limit
    File_size_limit=int(line.split(":")[1])

    global SMTP
    line=cfg.readline()
    SMTP=line.split(":")[1][:-1]

    global SMTP_port
    line=cfg.readline()
    SMTP_port=int(line.split(":")[1])

    global SMTP_user
    line=cfg.readline()
    SMTP_user=line.split(":")[1][:-1]

    global SMTP_password
    line=cfg.readline()
    SMTP_password=line.split(":")[1][:-1]

    global Email
    line=cfg.readline()
    Email=line.split(":")[1][:-1]

    if debug:
        print("File_size_limit :",File_size_limit)
        print("SMTP : ",SMTP)
        print("SMTP port : ",SMTP_port)


"""
EVENT QUEUE
"""
event_queue=[]


"""
OTHER FUNCTION DEFINITION
"""
def write_to_file(data):
    #Convert bytes to string
    url=data.decode("utf-8")
    #Write to file using File_pointer
    File_pointer.write(url+"\n")
    #Flush the write
    File_pointer.flush()


    global File_changed
    #Check for file change
    if File_changed:
        #Get size of current file
        file_size=stat("logs/"+Filename).st_size
        if file_size>File_size_limit:
            #Issue a file_change to event queue
            #Set work to event queue
            global event_queue
            element=[1,"file_change"]
            event_queue.append(element)
            #Set File_changed to false
            File_changed=False

            if debug:
                print("File change issued")

    if debug:
        print("Added to file : ",url)

def mailer_handler(file):
    mailer_thread=threading.Thread(target=asyn_mailer,args=(file,))
    mailer_thread.start()

def asyn_mailer(file):
    global Mailed
    if not Mailed:
        msg = MIMEMultipart()
        msg['From'] = Email
        msg['To'] = Email
        msg['Subject'] = "Website log"
        body = "Email logs"
        msg.attach(MIMEText(body, 'plain'))
        filename = file
        attachment = open("logs/"+filename, "rb")
        p = MIMEBase('application', 'octet-stream')
        p.set_payload((attachment).read())
        encoders.encode_base64(p)
        p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
        msg.attach(p)
        print(SMTP,SMTP_port)
        s = smtplib.SMTP(SMTP,SMTP_port)
        s.starttls()
        s.login(SMTP_user,SMTP_password)
        text = msg.as_string()
        s.sendmail(Email,Email, text)
        s.quit()

    #Set Mailed as true
    Mailed=True

def get_new_filename():
    #Close old File pointer
    global File_pointer
    File_pointer.flush()
    File_pointer.close()

    global Filename
    #Getting the latest count of the log
    count=int(Filename.split(".")[0].split("_")[1])
    #New count
    new_count=count+1
    #Filename format log_number.log
    new_filename="log_"+str(new_count)+".log"
    #Update file pointer
    File_pointer=open("logs/"+new_filename,"w")

    if debug:
        print("Change in filename : ",new_filename)

    #Set mail work to event queue
    global event_queue
    element=[2,Filename]
    event_queue.append(element)
    #Set mailed to false
    global Mailed
    Mailed=False

    #Update global variable
    Filename=new_filename
    global File_changed
    File_changed=True

"""
MODULE DEFINITION
"""
#DNS sniffer function definition
def dns_sniffer():
    #Callback function
    def callback(DNS_PACKET):
        #Extract url from the request
        url=DNS_PACKET[DNSQR].qname
        #Append to event_queue with valid format
        element=[0,url]
        global event_queue
        event_queue.append(element)

    #Set filter to "dest udp port 53", since default port for dns is 53
    BPF_FILTER = f"udp port 53"
    #sniff for dns packets
    sniff(filter=BPF_FILTER, prn=callback)


#Controller function definition
def controller():
    while True:
        #Check if queue is not empty
        while len(event_queue)!=0:
            #If not, pop the first elemnt
            element=event_queue.pop(0)
            #Extract id and message
            id=element[0]
            message=element[1]

            #Switch case
            if(id==0):
                write_to_file(message)
            elif(id==1):
                get_new_filename()
            elif(id==2):
                mailer_handler(message)


"""
Main Function definition
"""
init_global_variables()
sniffer_thread=threading.Thread(target=dns_sniffer)
controller_thread=threading.Thread(target=controller)
#Start the threads
sniffer_thread.start()
controller_thread.start()
#Indefinte waiting
sniffer_thread.join()
controller_thread.join()
