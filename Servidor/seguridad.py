import hmac
import hashlib
from time import time
from Crypto.Cipher import AES
import unittest

base = 16
pad = lambda s: s + (base - len(s) % base) * chr(base - len(s) % base)
unpad = lambda s : s[0:-ord(s[-1])]

class Seguridad:


	def __init__(self, AES, MAC):
		self.llaveAES= AES
		self.iv = '123456789abcdefg'
		self.llaveMAC = MAC

	def encriptar(self,msg):
		cifrador = AES.new(self.llaveAES,AES.MODE_CFB,self.iv)
		return cifrador.encrypt(msg)
		
	def desencriptar(self,msgen):
		decipher = AES.new(self.llaveAES,AES.MODE_CFB,self.iv)		
		return decipher.decrypt(msgen)
		
	def generarMAC(self,msg):
		m = hmac.new(self.llaveMAC,msg,hashlib.sha256)
		return m.digest()
		
	def compararMAC(self,msg,h):
		mac = hmac.new(self.llaveMAC,msg,hashlib.sha256).digest()
		if hmac.compare_digest(mac,h):
			return True
		else:
			return False
			
			
'''			
encriptador = Seguridad('23212345123456789123456723212345','qwerty')
tiempo_incial = time()
mensaje = 'Este es un mensaje de prueba'
msgencrip=encriptador.encriptar(mensaje)
print 'Encriptado' ,msgencrip
macenviado = encriptador.generarMAC(msgencrip)
print macenviado
#COMPARACION DEL MAC QUE FUE ENVIADO CON EL MAC QUE SE GENERA CON EL MENSAJE
encriptador.compararMAC(msgencrip, macenviado)
#COMPARACION DEL MAC QUE SE GENERA CON EL MENSAJE CON UN MAC MODIFICADO
encriptador.compararMAC(msgencrip, 'gdQbF635slk6GjRvZYeB5MPNzc7Zpxm6Tmxvo4F4VM8=')
print encriptador.desencriptar(msgencrip)
tf = time()
print 'Velocidad Promedio',len(mensaje) , (len(mensaje)/(tf - tiempo_incial)),'Bytes/s'
'''







