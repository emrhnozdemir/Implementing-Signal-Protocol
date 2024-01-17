import time
import sympy
import warnings
import sys
import math
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random # a bit better secure random number generation 
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import os
import re
import json


API_URL = 'http://harpoon1.sabanciuniv.edu:9999'

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b

stuID = 0
stuIDB = 0
IKey_Ser = Point(0x1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9, 0xce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff, E)
IKey_Pr = 0
IKey_Pub = P
SPK_a_Pr = 0
SPK_a_Pub = P
K_HMAC = b''
K_KDF = b''
K_ENC = b''
K_HMAC_M = b''
OTK_Pri_List = [0]*10
OTK_Pub_List = [P]*10
decrypted_msg_list = [""] * 5

def IKRegReq(h,s,x,y):
  mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
  print("Sending message is: ", mes)
  response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
  print(response.json())

def IKRegVerify(code):
  mes = {'ID':stuID, 'CODE': code}
  print("Sending message is: ", mes)
  response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
  if((response.ok) == False): raise Exception(response.json())
  else:
      print(response.json())
      f = open('Identity_Key.txt', 'w')
      f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
      f.close()

def SPKReg(h,s,x,y):
  mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
  print("Sending message is: ", mes)
  response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)
  print(response.json())			

def OTKReg(keyID,x,y,hmac):
  mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
  print("Sending message is: ", mes)
  response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
  print(response.json())
  if((response.ok) == False): return False
  else: return True


def ResetIK(rcode):
  mes = {'ID':stuID, 'RCODE': rcode}
  print("Sending message is: ", mes)
  response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
  print(response.json())
  if((response.ok) == False): return False
  else: return True

def ResetSPK(h,s):
  mes = {'ID':stuID, 'H': h, 'S': s}
  print("Sending message is: ", mes)
  response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
  print(response.json())
  if((response.ok) == False): return False
  else: return True


def ResetOTK(h,s):
  mes = {'ID':stuID, 'H': h, 'S': s}
  print("Sending message is: ", mes)
  response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
  if((response.ok) == False): print(response.json())

############## The new functions of phase 2 ###############
def PseudoSendMsg(h,s):
  mes = {'ID':stuID, 'H': h, 'S': s}
  print("Sending message is: ", mes)
  response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
  print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
  mes = {'ID':stuID, 'H': h, 'S': s}
  print("Sending message is: ", mes)
  response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
  print(response.json())	
  if((response.ok) == True): 
      res = response.json()
      return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["IK.X"], res["IK.Y"], res["EK.X"], res["EK.Y"]

#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
  mes = {'ID':stuID, 'H': h, 'S': s}
  print("Sending message is: ", mes)
  response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
  print(response.json())      
  if((response.ok) == True): 
      res = response.json()
      return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
  mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
  print("Sending message is: ", mes)
  response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
  print(response.json())

############## The new functions of phase 3 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsgPH3(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

# Send a message to client idB
def SendMsg(idA, idB, otkID, msgid, msg, ikx, iky, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "IK.X": ikx, "IK.Y": iky, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    


# Receive KeyBundle of the client stuIDB
def reqKeyBundle(stuID, stuIDB, h, s):
    key_bundle_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's Key Bundle ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqKeyBundle"), json=key_bundle_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['IK.X'], res['IK.Y'], res['SPK.X'], res['SPK.Y'], res['SPK.H'], res['SPK.s'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0, 0, 0, 0, 0, 0, 0


#Status control. Returns #of messages and remained OTKs
def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']


############## The new functions of BONUS ###############

# Exchange partial keys with users 2 and 4
def ExchangePartialKeys(stuID, z1x, z1y, h, s):
    request_msg = {'ID': stuID, 'z1.x': z1x, 'z1.y': z1y, 'H': h, 'S': s}
    print("Sending your PK (z) and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangePartialKeys"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['z2.x'], res['z2.y'], res['z4.x'], res['z4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0


# Exchange partial keys with user 3
def ExchangeXs(stuID, x1x, x1y, h, s):
    request_msg = {'ID': stuID, 'x1.x': x1x, 'x1.y': x1y, 'H': h, 'S': s}
    print("Sending your x and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangeXs"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['x2.x'], res['x2.y'], res['x3.x'], res['x3.y'], res['x4.x'], res['x4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0, 0, 0

# Check if your conference key is correct
def BonusChecker(stuID, Kx, Ky):
    mes = {'ID': stuID, 'K.x': Kx, 'K.y': Ky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "BonusChecker"), json=mes)
    print(response.json())

def IKSetup():
  global IKey_Pr, IKey_Pub
  
  try:
    with open("Identity_Key.txt", "r") as file:
      for line in file:
        line = line.strip()
        parts = line.split(":")
        if parts[0] == "IK.Prv":
          IKey_Pr = int(parts[1])
        elif parts[0] == "IK.Pub.x":
          IKey_Pub_x = int(parts[1])
        elif parts[0] == "IK.Pub.y":
          IKey_Pub_y = int(parts[1])

      IKey_Pub = Point(IKey_Pub_x, IKey_Pub_y, E)
      return False

  except FileNotFoundError:
    IKey_Pr = Random.new().read(int(math.log(n-1,2)))
    IKey_Pr = int.from_bytes(IKey_Pr, byteorder='big') % n
    IKey_Pub = IKey_Pr * P
    return True
  

def generateSignature(m_byte):
  k = Random.new().read(int(math.log(n-2,2)))
  k = int.from_bytes(k, byteorder='big') % n

  R = k * P
  r = R.x % n

  r_byte = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
  data_byte = r_byte + m_byte

  hashed_obj = SHA3_256.new(data_byte)
  hashed_byte = hashed_obj.digest()
  h = int.from_bytes(hashed_byte, byteorder='big') % n

  s = (k - (IKey_Pr * h)) % n 

  return h, s

def IK_Register():

  m_byte = stuID.to_bytes((stuID.bit_length() + 7) // 8, byteorder='big')
  h, s = generateSignature(m_byte)
  
  IKRegReq(h, s, IKey_Pub.x, IKey_Pub.y)


def IK_Verify():
  code = int(input("Enter the code: "))
  IKRegVerify(code)


def IK_Reset():
  rcode = int(input("Enter the reset code: "))
  ResetIK(rcode)
  os.remove("Identity_Key.txt")
  print("Identity Key is deleted")


def SPK_Register():
  global SPK_a_Pr, SPK_a_Pub
  s_a = Random.new().read(int(math.log(n-1,2)))
  SPK_a_Pr = int.from_bytes(s_a, byteorder='big') % n
  SPK_a_Pub = SPK_a_Pr * P

  SPK_a_Pub_x_byte = SPK_a_Pub.x.to_bytes((SPK_a_Pub.x.bit_length() + 7) // 8, byteorder='big')
  SPK_a_Pub_y_byte = SPK_a_Pub.y.to_bytes((SPK_a_Pub.y.bit_length() + 7) // 8, byteorder='big')
  m_byte = SPK_a_Pub_x_byte + SPK_a_Pub_y_byte

  h, s = generateSignature(m_byte)
  SPKReg(h, s, SPK_a_Pub.x, SPK_a_Pub.y)


def SPK_Reset():
  m_byte = stuID.to_bytes((stuID.bit_length() + 7) // 8, byteorder='big')

  h, s = generateSignature(m_byte)
  ResetSPK(h, s)


def Generate_K_HMAC():
  global K_HMAC
  T = SPK_a_Pr * IKey_Ser
  T_y_byte = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
  T_x_byte = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
  m = b'TheHMACKeyToSuccess'
  U_byte = m + T_y_byte + T_x_byte
  hashed_obj = SHA3_256.new(U_byte)
  K_HMAC = hashed_obj.digest()
  print("HMAC Key is generated")


def OTK_Register():
  global OTK_Pri_List, OTK_Pub_List
  for i in range(0, 10):
    OTK_Pr = Random.new().read(int(math.log(n-1,2)))
    OTK_Pr = int.from_bytes(OTK_Pr, byteorder='big') % n
    OTK_Pub = OTK_Pr * P

    
    OTK_Pub_x_byte = OTK_Pub.x.to_bytes((OTK_Pub.x.bit_length() + 7) // 8, byteorder='big')
    OTK_Pub_y_byte = OTK_Pub.y.to_bytes((OTK_Pub.y.bit_length() + 7) // 8, byteorder='big')
    message = OTK_Pub_x_byte + OTK_Pub_y_byte
    
    hmac = HMAC.new(K_HMAC, digestmod=SHA256)
    hmac.update(message)
    hmac = hmac.hexdigest() 
    OTKReg(i, OTK_Pub.x, OTK_Pub.y, hmac)
    OTK_Pri_List[i] = OTK_Pr
    OTK_Pub_List[i] = OTK_Pub


def OTK_Reset():
    m_byte = stuID.to_bytes((stuID.bit_length() + 7) // 8, byteorder='big')
    h, s = generateSignature(m_byte)
    ResetOTK(h, s)
    print("One-Time Pre-Keys are deleted")

def generateSessionKey(id, IK_B_Pub, EK_B_Pub):
    
  T1 = IK_B_Pub * SPK_a_Pr
  T2 = EK_B_Pub * IKey_Pr
  T3 = EK_B_Pub * SPK_a_Pr
  T4 = EK_B_Pub * OTK_Pri_List[id]

  T1_x_byte = T1.x.to_bytes((T1.x.bit_length() + 7) // 8, byteorder='big')
  T1_y_byte = T1.y.to_bytes((T1.y.bit_length() + 7) // 8, byteorder='big')
  T2_x_byte = T2.x.to_bytes((T2.x.bit_length() + 7) // 8, byteorder='big')
  T2_y_byte = T2.y.to_bytes((T2.y.bit_length() + 7) // 8, byteorder='big')
  T3_x_byte = T3.x.to_bytes((T3.x.bit_length() + 7) // 8, byteorder='big')
  T3_y_byte = T3.y.to_bytes((T3.y.bit_length() + 7) // 8, byteorder='big')
  T4_x_byte = T4.x.to_bytes((T4.x.bit_length() + 7) // 8, byteorder='big')
  T4_y_byte = T4.y.to_bytes((T4.y.bit_length() + 7) // 8, byteorder='big')
  U_byte = T1_x_byte + T1_y_byte + T2_x_byte + T2_y_byte + T3_x_byte + T3_y_byte + T4_x_byte + T4_y_byte + b'WhatsUpDoc'
  hashed_obj = SHA3_256.new(U_byte)
  K_S = hashed_obj.digest()
  return K_S

def receiveMessage():
  global K_KDF, K_ENC, K_HMAC_M, decrypted_msg_list 
  m_byte = stuID.to_bytes((stuID.bit_length() + 7) // 8, byteorder='big')
  h, s = generateSignature(m_byte)
  ID_B , OTK_ID, MSG_ID, MSG, IK_X, IK_Y, EK_X, EK_Y = ReqMsg(h, s)
  IK_B_Pub = Point(IK_X, IK_Y, E)
  EK_B_Pub = Point(EK_X, EK_Y, E)
  
  if MSG_ID == 1: 
    K_KDF = generateSessionKey(OTK_ID, IK_B_Pub, EK_B_Pub)
  else:  
    hashed_obj = SHA3_256.new(K_ENC + K_HMAC_M + b'OhanaMeansFamily')
    K_KDF = hashed_obj.digest()
  
  hashed_obj = SHA3_256.new(K_KDF + b'JustKeepSwimming')
  K_ENC = hashed_obj.digest()
  hashed_obj = SHA3_256.new(K_KDF + K_ENC + b'HakunaMatata')
  K_HMAC_M = hashed_obj.digest()
  
  msg_byte = MSG.to_bytes((MSG.bit_length() + 7) // 8, byteorder='big')
  msg_hmac = msg_byte[len(msg_byte)-32:]
  msg = msg_byte[8:len(msg_byte)-32]

  hmac = HMAC.new(K_HMAC_M, digestmod=SHA256)
  hmac.update(msg)
  hmac = hmac.digest()

  
  if hmac == msg_hmac:
    ctext = msg_byte[:len(msg_byte)-32]
    c = AES.new(K_ENC, AES.MODE_CTR, nonce=ctext[:8])
    ptext = c.decrypt(ctext[8:])
    decrypted_msg = ptext.decode()
  else:
    decrypted_msg = "INVALIDHMAC"

  Checker(stuID, ID_B, MSG_ID, decrypted_msg)
  decrypted_msg_list[MSG_ID-1] = decrypted_msg

def checkDeletedMessages():
  m_byte = stuID.to_bytes((stuID.bit_length() + 7) // 8, byteorder='big')
  h, s = generateSignature(m_byte)
  msg_list = ReqDelMsg(h,s)
  if msg_list == None:
    msg_list = [-1]

  for i in range(5):
    if i + 1 in msg_list:
      print("Message " + str(i + 1) + " - Was deleted by sender - X")
    else:
      if decrypted_msg_list[i] != "INVALIDHMAC":
        print("Message " + str(i + 1) + " - " + decrypted_msg_list[i] + " - Read")

def phase2():
  m_byte = stuID.to_bytes((stuID.bit_length() + 7) // 8, byteorder='big')
  h, s = generateSignature(m_byte)
  PseudoSendMsgPH3(h, s)
  for i in range(5):
    receiveMessage()

  checkDeletedMessages()

def verifySPKSignature(IK_x, IK_y, h, s, SPK_x, SPK_y):
  IK_Pub = Point(IK_x, IK_y, E)
  V = s * P + h * IK_Pub
  v = V.x % n

  SPK_Pub = Point(SPK_x, SPK_y, E)

  v_byte = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big')
  x_byte = SPK_Pub.x.to_bytes((SPK_Pub.x.bit_length() + 7) // 8, byteorder='big')
  y_byte = SPK_Pub.y.to_bytes((SPK_Pub.y.bit_length() + 7) // 8, byteorder='big')

  data_byte = v_byte + x_byte + y_byte

  hashed_obj = SHA3_256.new(data_byte)
  h_prime = hashed_obj.digest()
  h_prime = int.from_bytes(h_prime, byteorder='big') % n

  if h_prime == h:
    return True
  else:
    return False
  
  
def SendMessage():
  while 1:
    id = input("Enter the ID of the receiver: ")
    if(id.isnumeric() == False):
      print("Wrong input")
    else:
      id = int(id)
      if(id < 10000):
        print("Wrong input")
      else:
        stuIDB = id
        break
  
  m_byte = stuIDB.to_bytes((stuIDB.bit_length() + 7) // 8, byteorder='big')
  IK_B_h, IK_B_s = generateSignature(m_byte)
  KeyID, IK_X, IK_Y, SPK_X, SPK_Y, h, s, OTK_X, OTK_Y = reqKeyBundle(stuID, stuIDB, IK_B_h, IK_B_s)
  
  if verifySPKSignature(IK_X, IK_Y, h, s, SPK_X, SPK_Y) == False:
    print("SPK Signature is not verified")
    return
  
  IK_B_Pub = Point(IK_X, IK_Y, E)
  SPK_B_Pub = Point(SPK_X, SPK_Y, E)
  OTK_B_Pub = Point(OTK_X, OTK_Y, E)
  
  EK_A_Pr = Random.new().read(int(math.log(n-1,2)))
  EK_A_Pr = int.from_bytes(EK_A_Pr, byteorder='big') % n
  EK_A_Pub = EK_A_Pr * P

  T1 = SPK_B_Pub * IKey_Pr
  T2 = IK_B_Pub * EK_A_Pr
  T3 = SPK_B_Pub * EK_A_Pr
  T4 = OTK_B_Pub * EK_A_Pr

  T1_x_byte = T1.x.to_bytes((T1.x.bit_length() + 7) // 8, byteorder='big')
  T1_y_byte = T1.y.to_bytes((T1.y.bit_length() + 7) // 8, byteorder='big')
  T2_x_byte = T2.x.to_bytes((T2.x.bit_length() + 7) // 8, byteorder='big')
  T2_y_byte = T2.y.to_bytes((T2.y.bit_length() + 7) // 8, byteorder='big')
  T3_x_byte = T3.x.to_bytes((T3.x.bit_length() + 7) // 8, byteorder='big')
  T3_y_byte = T3.y.to_bytes((T3.y.bit_length() + 7) // 8, byteorder='big')
  T4_x_byte = T4.x.to_bytes((T4.x.bit_length() + 7) // 8, byteorder='big')
  T4_y_byte = T4.y.to_bytes((T4.y.bit_length() + 7) // 8, byteorder='big')
  U_byte = T1_x_byte + T1_y_byte + T2_x_byte + T2_y_byte + T3_x_byte + T3_y_byte + T4_x_byte + T4_y_byte + b'WhatsUpDoc'
  hashed_obj = SHA3_256.new(U_byte)
  K_S = hashed_obj.digest()

  counter = 1

  while counter:
    if counter == 1:
      K_KDF = K_S
    else:
      hashed_obj = SHA3_256.new(K_ENC + K_HMAC_M + b'OhanaMeansFamily')
      K_KDF = hashed_obj.digest()
    
    hashed_obj = SHA3_256.new(K_KDF + b'JustKeepSwimming')
    K_ENC = hashed_obj.digest()
    hashed_obj = SHA3_256.new(K_KDF + K_ENC + b'HakunaMatata')
    K_HMAC_M = hashed_obj.digest()
    print("Enter 0 to exit")
    msg = input("Enter the " + str(counter) + ". message: ")
    counter += 1
    if msg == "0":
      break

    nonce = Random.new().read(8)
    msg = bytes(msg, 'utf-8')
    hmac = HMAC.new(K_HMAC_M, digestmod=SHA256)
    hmac.update(msg)
    hmac = hmac.digest()
    c = AES.new(K_ENC, AES.MODE_CTR, nonce=nonce)
    ctext = c.encrypt(msg)
    ctext = nonce + ctext + hmac
    ctext = int.from_bytes(ctext, byteorder='big')
    SendMsg(stuID, stuIDB, KeyID, 1, ctext, IK_X, IK_Y, EK_A_Pub.x, EK_A_Pub.y)


def checkStatus():
  m_byte = stuID.to_bytes((stuID.bit_length() + 7) // 8, byteorder='big')
  h,s = generateSignature(m_byte)
  Status(stuID, h, s)
  ans = input("Do you want to generate new OTKs? (y/n): ")
  if ans == 'y' or ans == 'Y':
    OTK_Reset()
    OTK_Register()
  

def bonus():
  Z_Pr = Random.new().read(int(math.log(n-2,2)))
  Z_Pr = int.from_bytes(Z_Pr, byteorder='big') % n
  Z_Pub = Z_Pr * P

  Z_Pub_x_byte = Z_Pub.x.to_bytes((Z_Pub.x.bit_length() + 7) // 8, byteorder='big')
  Z_Pub_y_byte = Z_Pub.y.to_bytes((Z_Pub.y.bit_length() + 7) // 8, byteorder='big')
  m_byte = Z_Pub_x_byte + Z_Pub_y_byte
  h, s = generateSignature(m_byte)

  Z2_x, Z2_y, Z4_x, Z4_y = ExchangePartialKeys(stuID, Z_Pub.x, Z_Pub.y, h, s)
  Z2 = Point(Z2_x, Z2_y, E)
  Z4 = Point(Z4_x, Z4_y, E)

  X1 = Z_Pr * (Z2 - Z4)
  X1_x_byte = X1.x.to_bytes((X1.x.bit_length() + 7) // 8, byteorder='big')
  X1_y_byte = X1.y.to_bytes((X1.y.bit_length() + 7) // 8, byteorder='big')
  m_byte = X1_x_byte + X1_y_byte 
  
  h, s = generateSignature(m_byte)

  X2_x, X2_y, X3_x, X3_y, X4_x, X4_y = ExchangeXs(stuID, X1.x, X1.y, h, s)
  X2 = Point(X2_x, X2_y, E)
  X3 = Point(X3_x, X3_y, E)
  X4 = Point(X4_x, X4_y, E)
  K = Z4 * 4 * Z_Pr + 3 * X1 + 2 * X2 + X3
  BonusChecker(stuID, K.x, K.y)

if IKSetup():
  IK_Register()
  IK_Verify()

SPK_Register()
Generate_K_HMAC()
OTK_Register()

IK_registered = True
SPK_registered = True
OTK_registered = True

option = 9
while option != 0:
  if IK_registered:
    print("\nPlease enter 1 for Reset of Identity Keys")
  else:
    print("\nPlease enter 1 for Registration of Identity Keys")

  if SPK_registered:
    print("Please enter 2 for Reset of Signature Public Keys")
  else:
    print("Please enter 2 for Registration of Signature Public Keys")
  
  if OTK_registered:
    print("Please enter 3 for Reset of One-Time Pre-Key")
  else:
    print("Please enter 3 for Registration of One-Time Pre-Key")
  
  print("Please enter 4 for Receiving Messages")
  print("Please enter 5 for Sending Messages")
  print("Please enter 6 for Checking Status")
  print("Please enter 7 for Generating Conference Key")
  print("Please enter 0 to Exit")
  option = input("Enter: ")
  print("\n")

  if option.isnumeric() == False:
    print("Wrong input")

  else:
    option = int(option)

    if option == 1:
      if IK_registered:
        IK_Reset()
        OTK_Register = False
        SPK_Register = False
      else:
        IK_Register()
        IK_Verify()

      IK_registered = not IK_registered

    elif option == 2: 
      if SPK_registered:
        OTK_Reset()
        SPK_Reset()
        OTK_registered = False
      else:
        SPK_Register()
        Generate_K_HMAC()
      
      SPK_registered = not SPK_registered

    elif option == 3:
      if OTK_registered:
        OTK_Reset()
      else:
        OTK_Register()
      
      OTK_registered = not OTK_registered
    
    elif option == 4:
      phase2()
    
    elif option == 5:
      SendMessage()

    elif option == 6:
      checkStatus()
    
    elif option == 7:
      bonus()

    elif option == 0:
      if IK_registered:
        OTK_Reset()
        SPK_Reset()
      print("Exiting...")

    else:
      print("Wrong input")
    
