from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC,SHA512
from Crypto.Protocol.KDF import PBKDF2
from getpass import getpass
from binascii import unhexlify, hexlify
import base64
from sys import exit
from math import ceil
import os
import string
import time

class pypassword:
  def __init__(self, file, blockSize):
    self.file = file
    self.bs = blockSize
    self.key = None
    self.hmac = None
    self.websites = None
    self.version = "pypassword v0.01"
  
  def showMenu(self):
    print("")
    if self.websites == None:
      print(self.version + " (0 stored password)")
    elif len(self.websites) == 1:
      print(self.version + " (" + str(len(self.websites)) + " stored password)")
    else:
      print(self.version + " (" + str(len(self.websites)) + " stored passwords)")
    print("""
      (g) Get a password;
      (a) Add a password;
      (m) Modify a password;
      (d) Delete a password;
      (v) View list of stored passwords;
      (r) Reset encrypted file;
      (q) Quit.
      """)
    
  def clearConsole(self):
    os.system('cls' if os.name == 'nt' else 'clear')
    
  # add pad to text so total length is a multiple of AES block size
  # if blocksize = 16, len(text) = 12 -> pad = 04040404
  # if blocksize = 16, len(text) = 16 -> pad = 10101010 10101010 10101010 10101010
  def pad(self, s):
    return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

  # remove padding and return text
  def unpad(self, s):
    return s[:-ord(s[len(s)-1:])]

  def validHmac(self, hmac):
    with open(self.file) as f:
      line = f.readline().split()
      if not line:
        return IOError
      self.hmac = line[0]
    return self.hmac == hmac
      
  # read the data file
  def parseData(self):
    with open(self.file) as f:
      line = f.readline().split()
      if not line:
        return None
      self.hmac = line[0]
  
      self.websites = {}
      line = f.readline().split()
      while len(line) == 3:
        url = self.decrypt(line[0])
        username = self.decrypt(line[1])
        password = self.decrypt(line[2])
        self.websites[url] = [username, password]
        line = f.readline().split()

  def writeData(self):
    with open(self.file, "w+") as f:
      f.write(self.hmac + "\n")
      if self.websites is not None:
        for site in self.websites:
          f.write(self.encrypt(site) + " " + self.encrypt(self.websites[site][0]) + " " + self.encrypt(self.websites[site][1]) + "\n")

  # login information
  # generate key and hmac from username/password
  def prompt(self):
    username = raw_input("username: ")
    password = getpass('password: ')
    # generate key from username/password
    key = PBKDF2(password, SHA512.new(username).hexdigest(), dkLen=32, count=20000)
    # hmac
    hmac = HMAC.new(key, msg=username, digestmod=SHA512).hexdigest()
    return (key, hmac)

  def encrypt(self, text):
    padded = self.pad(text).encode("hex")
    iv = Random.new().read(self.bs)
    cipher = AES.new(self.key.decode("hex"), AES.MODE_CBC, iv)
    return iv.encode("hex") + cipher.encrypt(padded.decode("hex")).encode("hex")
  
  def decrypt(self, text):
    iv = text[:2*self.bs].decode("hex")
    ciphertext = text[2*self.bs:].decode("hex")
    cipher = AES.new(self.key.decode("hex"), AES.MODE_CBC, iv)
    message = cipher.decrypt(ciphertext)
    return self.unpad(message)

  # add a website username/password
  def addWebsite(self):
    self.viewList()
    url = raw_input("\nwebsite url: ")
    username = raw_input("username: ")
    password = raw_input("password: ")
    self.websites[url.lower()] = [username, password]
    self.writeData()
  
  # remove a website username/password
  def remWebsite(self):
    self.viewList()
    url = raw_input("\nwebsite url: ")
    if url in self.websites.keys():
      print("password removed for " + url)
      del self.websites[url]
      self.writeData()
    else:
      print("No password for " + url)
  
  # modify a website username/password
  def modWebsite(self):
    self.viewList()
    url = raw_input("\nwebsite url: ")
    if url in self.websites.keys():
      username = raw_input("username: ")
      password = raw_input("password: ")
      self.websites[url] = [username, password]
      self.writeData()
    else:
      print("No password for " + url)
      
  # search for a password
  def getWebsite(self):
    self.viewList()
    url = raw_input("\nwebsite url: ")
    if url in self.websites.keys():
      [username, password] = self.websites[url]
      print("username: "  + username + "\npassword: " + password)
    else:
      print("No password for " + url)
  
  # print list of password
  def viewList(self):
    self.clearConsole()
    if self.websites is not None:
      print("URL List:")
      urls = self.websites.keys()
      for url in urls:
        print(url)
  
  # generate a password
  # Not used in current implementation
  def genpassword(self):
    length = raw_input("number of characters [30]: ")
    if length == "":
      length = 30
    else:
      length = int(length)
    alphabet = "".join((string.letters, string.digits, string.punctuation))
    pw = "".join(random.choice(alphabet) for _ in range(length))
    print(pw)

# Set file path here
file = "./secret.txt"

# main
n = 0
blockSize = 16
obj = pypassword(file, blockSize)
obj.clearConsole()

# Check if file exist
if not os.path.isfile(file) or os.stat(file).st_size == 0:
  print "Create a new master username/password"
  obj.key, obj.hmac = obj.prompt()
  obj.writeData()
else:
  # authenticate and parse
  while n < 3:
    key, hmac = obj.prompt()    
    # validate username/password
    if obj.validHmac(hmac):
      obj.key = key.encode('hex')
      obj.parseData()
      break
    else:
      print("wrong username/password combinations.")
      time.sleep(1)
      n = n + 1

# Menu and options
ans = True
while ans and n<3:
  obj.showMenu()
  ans=raw_input("> ")
  obj.clearConsole()
  
  if ans=="a":
    obj.addWebsite()
    
  elif ans=="d":
    obj.remWebsite()
  
  elif ans=="g":
    obj.getWebsite()
  
  elif ans=="m":
    obj.modWebsite()
  
  elif ans=="r":
    obj.websites = None
    obj.writeData()
    print("Resetting file.")
  
  elif ans=="v":
    obj.viewList()
  
  elif ans=="q":
    ans = False
  
  else:
    print("Invalid input, shame!")