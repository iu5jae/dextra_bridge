#!/usr/bin/python3

#    dextra_bridge
#
#    Created by Antonio Matraia (IU5JAE) on 08/06/2020.
#    Copyright 2020 Antonio Matraia (IU5JAE). All rights reserved.

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import threading
import time
import logging
import socket
import sys
import queue
import configparser
from logging.handlers import RotatingFileHandler
import re
import os
import signal

ver = '220925'

a_connesso = False
b_connesso = False
a_fault = False
b_fault = False
q_ab = queue.Queue() # coda pacchetti A -> B 
q_ba = queue.Queue() # coda pacchetti B -> A 

lock_a = threading.Lock()
lock_b = threading.Lock()
lock_wl = threading.Lock()
lock_bl = threading.Lock()
lock_conn_a = threading.Lock()
lock_conn_b = threading.Lock()
lock_dir = threading.Lock()
a_b_dir = False # direzione attiva A --> B
b_a_dir = False # direzione attiva B --> A
bufferSize = 1024

## config
config = configparser.ConfigParser()

if (len(sys.argv) != 2):
  print('Invalid Number of Arguments')
  logging.error('Invalid Number of Arguments')
  print('use: dextra_bridge <configuration file>')
  logging.error('use: dextra_bridge <configuration file>')
  sys.exit()
  
config_file = sys.argv[1].strip()
config.read(config_file)
log_file = config['general']['log_file'] 
whitelist_file = config['general']['whitelist_file'] 
blacklist_file = config['general']['blacklist_file']

try:
  log_maxBytes = int(config['general']['log_maxBytes'])
except:
  log_maxBytes = 1000000
try:    
  log_backupCount = int(config['general']['log_backupCount'])
except:
  log_backupCount = 10  

try:
  ack_period = float(config['general']['ack_period'])
except:
  ack_period = 3.0
  
try:
  ack_tout = float(config['general']['ack_tout'])
except:
  ack_tout = 30.0  
  
ack_time_a = ack_tout 
ack_time_b = ack_tout 


# "A" side
XRF_A = config['A']['XRF']
UDP_IP_A = config['A']['address']
PORT_A = config['A']['port']
CALL_A = config['A']['call'] 
MODULE_A = config['A']['module']
XRF_MODULE_A = config['A']['XRF_module']

try:
  UDP_PORT_A = int(config['A']['port'])
except:
  UDP_PORT_A = 30001  

try:
  FILTERING_A = int(config['A']['filtering'])
  if (FILTERING_A != 0):
    FILTERING_A = 1
except:
  FILTERING_A = 0  


# "B" side
XRF_B = config['B']['XRF']
UDP_IP_B = config['B']['address']
PORT_B = config['B']['port']
CALL_B = config['B']['call'] 
MODULE_B = config['B']['module']
XRF_MODULE_B = config['B']['XRF_module']

try:
  UDP_PORT_B = int(config['B']['port'])
except:
  UDP_PORT_B = 30001  

try:
  FILTERING_B = int(config['B']['filtering'])
  if (FILTERING_B != 0):
    FILTERING_B = 1
except:
  FILTERING_B = 0  

##log
logging.basicConfig(handlers=[RotatingFileHandler(log_file, maxBytes=log_maxBytes, backupCount=log_backupCount)], format='%(asctime)s %(message)s', datefmt='%d/%m/%Y %H:%M:%S', level=logging.INFO)


while (len(CALL_A) != 8):
	CALL_A += ' '

while (len(CALL_B) != 8):
	CALL_B += ' '
    
while (len(XRF_A) != 8):
	XRF_A += ' '

while (len(XRF_B) != 8):
	XRF_B += ' '

if (CALL_A[0:3] == 'XRF'):
  VER_A = 2
else:
  VER_A = 0

if (CALL_B[0:3] == 'XRF'):
  VER_B = 2
else:
  VER_B = 0  
    
MESSAGE_A = CALL_A + MODULE_A[0] + XRF_MODULE_A[0] + ' ' # stringa connessione "A"
MESSAGE_B = CALL_B + MODULE_B[0] + XRF_MODULE_B[0] + ' ' # stringa connessione "B"

DISCONN_A = CALL_A + MODULE_A[0] + '  '  # stringa disconnessione "A"
DISCONN_B = CALL_B + MODULE_B[0] + '  '  # stringa disconnessione "B"

# stringa di ACK connessione che dipende
# dalla versione del protocollo
if (VER_A == 2):
  ACK_A = XRF_A + XRF_MODULE_A[0] + MODULE_A + '\x00'
else:
  # ver 0
  ACK_A = MESSAGE_A.strip() + 'ACK'

if (VER_B == 2):
  ACK_B = XRF_B  + XRF_MODULE_B[0] + MODULE_B + '\x00'
else:
  ACK_B = MESSAGE_B.strip() + 'ACK'


CALL_A = CALL_A.strip()
CALL_B = CALL_B.strip()

while (len(CALL_A) != 7):
	CALL_A += ' '

while (len(CALL_B) != 7):
	CALL_B += ' '

keepalive_str_a = CALL_A + MODULE_A[0] + ' ' 
keepalive_str_b = CALL_B + MODULE_B[0] + ' ' 


# socket connessione A
sock_a = socket.socket(socket.AF_INET, 
                        socket.SOCK_DGRAM) 

sock_a.settimeout(ack_tout + 10.0)

# socket connessione B
sock_b = socket.socket(socket.AF_INET, 
                        socket.SOCK_DGRAM) 

sock_b.settimeout(ack_tout + 10.0)


def crc16_dstar(data, num):
# calcolo crc per DSTAR
        i = 0
        j = 0
        Temp = 0x0
        CRC = 0xFFFF
        for i in range(num):
          Temp = CRC
          CRC = Temp ^ data[i]
          for j in range(8):
            if (CRC & 1):
              CRC = ((CRC >> 1) ^ 0x8408) 
            else:
              CRC = (CRC >> 1) 
        return CRC ^ 0xFFFF       


def leggi_lista(f_l):
  lv_a = []
  lc_a = []
  lv_b = []
  lc_b = []
  logging.info('leggi_lista: lettura ' + f_l)
  try:
    with open(f_l) as f:
     for s in f:
       s = s.strip()
       if (len(s) > 0):
         # non si considerano i commenti
         if (s[0] != '#'):
           sdati = s.split(':')
           # la lista deve contenere 3 elemeti
           if (len(sdati) == 3):
             if (sdati[0].strip().lower() == 'via'):
               if (re.search('A', sdati[2].strip().upper())):
                 lv_a.append(sdati[1].strip().upper())
               if (re.search('B', sdati[2].strip().upper())):
                 lv_b.append(sdati[1].strip().upper())  
             if (sdati[0].strip().lower() == 'call'):
               if (re.search('A', sdati[2].strip().upper())):
                 lc_a.append(sdati[1].strip().upper())
               if (re.search('B', sdati[2].strip().upper())):
                 lc_b.append(sdati[1].strip().upper())  
  except Exception as e:
    logging.error('leggi_lista: errore leggendo il file ' + f_l + ' ' + str(e))
  
  pat_va = ''
  pat_vb = ''
  pat_ca = ''
  pat_cb = ''         
  for i in lv_a:
    pat_va += i+'|'         
  pat_v_a = pat_va[0:len(pat_va)-1]
           
  for i in lv_b:
    pat_vb += i+'|'              
  pat_v_b = pat_vb[0:len(pat_vb)-1]

  for i in lc_a:
    pat_ca += i+'|'              
  pat_c_a = pat_ca[0:len(pat_ca)-1]

  for i in lc_b:
    pat_cb += i+'|'   
  pat_c_b = pat_cb[0:len(pat_cb)-1]

  return [re.compile(pat_v_a), re.compile(pat_v_b), re.compile(pat_c_a), re.compile(pat_c_b)]


def passa(wl_v, wl_c, bl_v, bl_c, via, call):
  lock_wl.acquire()
  if (wl_v.match(via) or wl_c.match(call)):
    passaw = True
  else:
    passaw = False
  lock_wl.release()
  lock_bl.acquire()
  if (bl_v.match(via) or bl_c.match(call)):
    bloccab = True
  else:
    bloccab = False
  lock_bl.release()      
  return passaw and (not bloccab)

def signal_handler(signal, frame):
  global run, a_connesso, b_connesso
  logging.info('Arresto in corso ...')
  if a_connesso:
    q_ba.put(str.encode(DISCONN_A))
    logging.info('Disconnessione da A')
    time.sleep(2)
    a_connesso = False
  if b_connesso:
    q_ab.put(str.encode(DISCONN_B))
    logging.info('Disconnessione da B')
    time.sleep(2)
    b_connesso = False
  if ((not a_connesso) and (not b_connesso)):
    run = False
 

def conn (sock, lato):
    global a_connesso, b_connesso, a_fault, b_fault
    if (lato == 'A'):
      # print('conn: provo a connettere A') 
      logging.info('conn: provo a connettere A') 
      try:
        sock.sendto(str.encode(MESSAGE_A), (UDP_IP_A, UDP_PORT_A))
        msgFromServer = sock.recvfrom(bufferSize)
        sock_err = False
      except Exception as e:
        # print('conn: Errore connessione A ' + str(e))  
        logging.error('conn: Errore connessione A ' + str(e))
        sock_err = True
      if (not sock_err):  
        # print(msgFromServer[0][0:13])
        
        # scelgo la stringa giusta da verificare
        if (VER_A == 2):
          msg = msgFromServer[0][0:11]
        else:
          msg = msgFromServer[0][0:13]
        
        if (msg == str.encode(ACK_A)):
          # print('connesso A')
          logging.info('connesso A')
          lock_conn_a.acquire()
          a_connesso = True
          a_fault = False
          lock_conn_a.release()
          lock_a.acquire()
          ack_time_a = 0
          lock_a.release()
    if (lato == 'B'):
      # print('conn: provo a connettere B')  
      logging.info('conn: provo a connettere B')
      try:
        sock.sendto(str.encode(MESSAGE_B), (UDP_IP_B, UDP_PORT_B))
        msgFromServer = sock.recvfrom(bufferSize)
        sock_err = False
      except Exception as e:
        # print('conn: Errore connessione B ' + str(e)) 
        logging.error('conn: Errore connessione B ' + str(e))  
        sock_err = True
      if (not sock_err):  
        # print(msgFromServer[0][0:13])
        
        if (VER_B == 2):
          msg = msgFromServer[0][0:11]
        else:
          msg = msgFromServer[0][0:13]
        
        if (msg == str.encode(ACK_B)):
          # print('connesso B')
          logging.info('connesso B')
          lock_conn_b.acquire()
          b_connesso = True
          b_fault = False
          lock_conn_b.release()
          lock_b.acquire()
          ack_time_b = 0
          lock_b.release()

# invio dati a "A"
def send_a():
  while True:
    msg = q_ba.get()
    # print('send_a: invio pacchetto ad A')
    try: 
      sock_a.sendto(msg, (UDP_IP_A, UDP_PORT_A))
    except Exception as e:
      # print('send_a: errore invio ad A ' + str(e))
      logging.error('send_a: errore invio ad A ' + str(e))

# invio dati a "B" 
def send_b():
  while True:
    msg = q_ab.get()
    # print('send_b: invio pacchetto a B')
    try: 
      sock_b.sendto(msg, (UDP_IP_B, UDP_PORT_B))
    except Exception as e:
      # print('send_b: errore invio a B ' + str(e))
      logging.error('send_b: errore invio a B ' + str(e))

def rcv_a():
  global a_connesso, b_connesso, a_b_dir, b_a_dir, ack_time_a
  while True:
    if a_connesso:  
      try:
        msgFromServer = sock_a.recvfrom(bufferSize)
        # print(msgFromServer[0])
        if ((len(msgFromServer[0]) == 11) and (msgFromServer[0][9] != ' ')):
          # print('Connect')
          logging.info('rcv_a: Connesso')
          lock_conn_a.acquire()
          a_connesso = True
          lock_conn_a.release()
        if ((len(msgFromServer[0]) == 11) and (msgFromServer[0][9] == ' ')):
          # print('Disconnect')
          logging.info('rcv_a: Disconnesso')
          lock_conn_a.acquire()
          a_connesso = False
          lock_conn_a.release()
          # print(str(len(msgFromServer[0])) + ' -> ' + str(msgFromServer[0][0:4]))  
        if ((len(msgFromServer[0]) == 9) and (msgFromServer[0][0:8] == str.encode(XRF_A))):
          # print('Keepalive')
          lock_a.acquire()
          ack_time_a = 0
          lock_a.release()
        if ((len(msgFromServer[0]) == 56) and (msgFromServer[0][0:4] == b'DSVT') and (msgFromServer[0][4] == 0x10) and
           (msgFromServer[0][8] == 0x20)):
          if (a_connesso and b_connesso):
            if FILTERING_A:
              via = msgFromServer[0][26:34].decode('utf-8', 'backslashreplace').strip()
              call = msgFromServer[0][42:50].decode('utf-8', 'backslashreplace').strip()
              p = passa(wlv_a, wlc_a, blv_a, blc_a, via, call)
            else:
              p = True   
            # logging.info('rcv_a: Via/Call: ' + via + '/' + call + ' --> ' + str(p))
            if cross:
              bya_msg = bytearray(msgFromServer[0])
              bya_msg[25] = str.encode(XRF_MODULE_B.strip())[0]
              crc = crc16_dstar(bya_msg[15:54],39)
              bya_msg[54] = crc & 0xff
              bya_msg[55] = crc >> 8
              msg = bytes(bya_msg)
            else:
              msg = msgFromServer[0]   
            lock_dir.acquire()
            if p:
              a_b_dir = True
              b_b_dir = False
            else:
              a_b_dir = False
              b_b_dir = False
            lock_dir.release()
            if p:
              q_ab.put(msg)
             # print('DvHeader')
        if ((len(msgFromServer[0]) == 27) and (msgFromServer[0][0:4] == b'DSVT') and (msgFromServer[0][4] == 0x20) and
            (msgFromServer[0][8] == 0x20) and ((msgFromServer[0][14] & 0x40) == 0)):
          if (a_connesso and b_connesso and a_b_dir):
            q_ab.put(msgFromServer[0])
            # print('DvFrame')
  
        if ((len(msgFromServer[0]) == 27) and (msgFromServer[0][0:4] == b'DSVT') and (msgFromServer[0][4] == 0x20) and
            (msgFromServer[0][8] == 0x20) and ((msgFromServer[0][14] & 0x40) != 0)):
          if (a_connesso and b_connesso and a_b_dir):
            q_ab.put(msgFromServer[0])    
            # print('LastFrame')
       
      except Exception as e:
        # print('rcv A --> ' + str(e))
        logging.error('rcv_a: ' + str(e))
        
    else:
      time.sleep(1.0)   


def rcv_b():
  global a_connesso, b_connesso, a_b_dir, b_a_dir, ack_time_b
  while True:
    if b_connesso:
      try:
        msgFromServer = sock_b.recvfrom(bufferSize)
        # print(msgFromServer[0])
        if ((len(msgFromServer[0]) == 11) and (msgFromServer[0][9] != ' ')):
          # print('Connect')
          logging.info('rcv_b: Connesso')
          lock_conn_b.acquire()
          b_connesso = True
          lock_conn_b.release()
        if ((len(msgFromServer[0]) == 11) and (msgFromServer[0][9] == ' ')):
          # print('Disconnect')
          logging.info('rcv_b: Disconnesso')
          lock_conn_b.acquire()
          b_connesso = False
          lock_conn_b.release()
          # print(str(len(msgFromServer[0])) + ' -> ' + str(msgFromServer[0][0:4]))  
        if ((len(msgFromServer[0]) == 9) and (msgFromServer[0][0:8] == str.encode(XRF_B))):
          # print('Keepalive')
          lock_b.acquire()
          ack_time_b = 0
          lock_b.release()
        if ((len(msgFromServer[0]) == 56) and (msgFromServer[0][0:4] == b'DSVT') and (msgFromServer[0][4] == 0x10) and
           (msgFromServer[0][8] == 0x20)):
          if (a_connesso and b_connesso):
            if FILTERING_B:
              via = msgFromServer[0][26:34].decode('utf-8', 'backslashreplace').strip()
              call = msgFromServer[0][42:50].decode('utf-8', 'backslashreplace').strip()
              p = passa(wlv_b, wlc_b, blv_b, blc_b, via, call)
            else:
              p = True   
            # logging.info('rcv_b: Via/Call: ' + via + '/' + call + ' --> ' + str(p))
            if cross:
              bya_msg = bytearray(msgFromServer[0])
              bya_msg[25] = str.encode(XRF_MODULE_A.strip())[0]
              crc = crc16_dstar(bya_msg[15:54],39)
              bya_msg[54] = crc & 0xff
              bya_msg[55] = crc >> 8
              msg = bytes(bya_msg)
            else:
              msg = msgFromServer[0]  
            lock_dir.acquire()
            if p:
              b_a_dir = True
              a_b_dir = False
            else:
              b_a_dir = False
              a_b_dir = False
            lock_dir.release()
            if p:
              q_ba.put(msg)
            # print('DvHeader')
        if ((len(msgFromServer[0]) == 27) and (msgFromServer[0][0:4] == b'DSVT') and (msgFromServer[0][4] == 0x20) and
            (msgFromServer[0][8] == 0x20) and ((msgFromServer[0][14] & 0x40) == 0)):
          if (a_connesso and b_connesso and b_a_dir):
            q_ba.put(msgFromServer[0])
            # print('DvFrame')
        if ((len(msgFromServer[0]) == 27) and (msgFromServer[0][0:4] == b'DSVT') and (msgFromServer[0][4] == 0x20) and
            (msgFromServer[0][8] == 0x20) and ((msgFromServer[0][14] & 0x40) != 0)):
          if (a_connesso and b_connesso and b_a_dir):
            q_ba.put(msgFromServer[0])    
            # print('LastFrame')
   
      except Exception as e:
        # print('rcv B --> ' + str(e))
        logging.error('rcv_b: ' + str(e))
    else:
      time.sleep(1.0)



# clock per gestione keepalive
def clock ():
 global ack_time_a, ack_time_b, ack_tout
 t = ack_tout * 1.1
 while 1:
     # print('coda A -> B: ' + str(q_ab.qsize()) + '  coda B -> A: ' + str(q_ba.qsize()))
     if (ack_time_a < t):   
       lock_a.acquire()
       # logging.info('lock')
       ack_time_a +=0.5
       lock_a.release()
     if (ack_time_b < t):     
       lock_b.acquire()
       ack_time_b +=0.5
       lock_b.release()
     # logging.info('release')
     time.sleep(0.5)

# controllo connessioni
def check_conn():
  global a_connesso, b_connesso, a_fault, b_fault  
  while True:
    # print('ack_time_a = ' + str(ack_time_a))
    # print('ack_time_b = ' + str(ack_time_b))
    if (ack_time_a > ack_tout):
      lock_conn_a.acquire()
      a_connesso = False
      lock_conn_a.release()
      if not b_fault:
        logging.info('check_conn: Timeout - Connetto A')
        conn (sock_a, 'A')    
        
      if ((not b_fault) and (not a_fault) and (not a_connesso)):
        a_fault = True
        if b_connesso:
          q_ab.put(str.encode(DISCONN_B))
          b_connesso = False
          logging.info('check_conn: Disconnetto B per Fault A')
    time.sleep(ack_tout/4.0)  
    
    if (ack_time_b > ack_tout):
      lock_conn_b.acquire()
      b_connesso = False
      lock_conn_b.release()
      if not a_fault:
        logging.info('check_conn: Timeout - Connetto B')
        conn (sock_b, 'B')
      
      if ((not b_fault) and (not a_fault) and (not b_connesso)):
        b_fault = True
        if a_connesso:
          q_ba.put(str.encode(DISCONN_A))
          a_connesso = False
          logging.info('check_conn: Disconnetto A per Fault B')

    time.sleep(ack_tout/4.0)

# invio pacchetti keepalive
def keepalive():
  global ack_time_a, ack_time_b   
  while True:
    if (a_connesso):
        q_ba.put(str.encode(keepalive_str_a))
        # print('keepalive: Invio Keepalive A')
        
    if (b_connesso):
        q_ab.put(str.encode(keepalive_str_b))
        # print('keepalive: Invio Keepalive B')
       
    time.sleep(ack_period)  


def aggiorna_liste():
  global wlv_a, wlv_b, wlc_a, wlc_b
  global blv_a, blv_b, blc_a, blc_b
  file_data_ultima_wl = 0
  file_data_ultima_bl = 0  
  while True:
    time.sleep(60.0)
    file_data_wl = os.stat(whitelist_file).st_mtime
    file_data_bl = os.stat(blacklist_file).st_mtime
    if (file_data_wl != file_data_ultima_wl):
      lock_wl.acquire()
      [wlv_a, wlv_b, wlc_a, wlc_b] = leggi_lista(whitelist_file)
      lock_wl.release()
      file_data_ultima_wl = file_data_wl
    if (file_data_bl != file_data_ultima_bl):
      lock_bl.acquire()
      [blv_a, blv_b, blc_a, blc_b] = leggi_lista(blacklist_file)
      lock_bl.release()
      file_data_ultima_bl = file_data_bl


run = True
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

t_clock = threading.Thread(target = clock)
t_clock.daemon = True
t_conn = threading.Thread(target = check_conn)
t_conn.daemon = True
t_keep = threading.Thread(target = keepalive)
t_keep.daemon = True
t_send_a = threading.Thread(target = send_a)
t_send_a.daemon = True
t_send_b = threading.Thread(target = send_b)
t_send_b.daemon = True
t_rcv_a = threading.Thread(target = rcv_a)
t_rcv_a.daemon = True
t_rcv_b = threading.Thread(target = rcv_b)
t_rcv_b.daemon = True


# print('Dextra Bridge: avvio')
logging.info('Dextra Bridge Ver. ' + ver + ' : avvio')
logging.info('Versione Protocollo A: ' + str(VER_A))
logging.info('Versione Protocollo B: ' + str(VER_B))

if (XRF_A == XRF_B):
  logging.error('Non possibile utilizzare lo stesso XRF')
  sys.exit()

if (XRF_MODULE_A[0] != XRF_MODULE_B[0]):
  cross = True
  logging.info('Funzione cross-link Attivata')
else:
  cross = False
  logging.info('Funzione cross-link Disattivata') 

if ((FILTERING_A == 1) or (FILTERING_B == 1)):
  [wlv_a, wlv_b, wlc_a, wlc_b] = leggi_lista(whitelist_file)
  [blv_a, blv_b, blc_a, blc_b] = leggi_lista(blacklist_file)
  t_aggl =  threading.Thread(target = aggiorna_liste)
  t_aggl.daemon = True
  t_aggl.start()
  logging.info('Filtraggio Attivo')
else:
  logging.info('Filtraggio Disattivato')  

t_clock.start() 
t_conn.start()
t_keep.start()
t_send_a.start()
t_send_b.start()
t_rcv_a.start()
t_rcv_b.start()



while run:
  time.sleep(3.0)
logging.info('dextra_bridge correttamente arrestato')

