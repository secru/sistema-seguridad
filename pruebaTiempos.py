from time import time
from Crypto.Cipher import AES
from Crypto.Util import Counter

base = 16
pad = lambda s: s + (base - len(s) % base) * chr(base - len(s) % base)
unpad = lambda s : s[0:-ord(s[-1])]

llave= '23212345123456789123456723212345'
iv = '123456789abcdefg'

msg = 'Prueba'

#MODO ECB - Bloque tamano fijo
ti_ECB=time()
cifrador = AES.new(llave,AES.MODE_ECB)
msgen = cifrador.encrypt(pad(msg))
#print msgen

decipher = AES.new(llave,AES.MODE_ECB)		
unpad(decipher.decrypt(msgen))
tf_ECB=time()
tiempoECB=tf_ECB-ti_ECB
print 'ECB' ,tiempoECB

#MODO CFB
ti_CFB=time()
cifrador = AES.new(llave,AES.MODE_CFB,iv)
msgen=cifrador.encrypt(msg)
#print msgen

decipher = AES.new(llave,AES.MODE_CFB,iv)		
decipher.decrypt(msgen)
tf_CFB=time()
tiempoCFB=tf_CFB-ti_CFB
print 'CFB' , tiempoCFB
CFB =['CFB' , tiempoCFB]

#MODO CBC - Bloque tamano fijo
ti_CBC=time()
cifrador = AES.new(llave,AES.MODE_CBC,iv)
msgen=cifrador.encrypt(pad(msg))
#print msgen

decipher = AES.new(llave,AES.MODE_CBC,iv)		
unpad(decipher.decrypt(msgen))
tf_CBC=time()
tiempoCBC=tf_CBC-ti_CBC
print 'CBC' ,tiempoCBC
CBC=['CBC' ,tiempoCBC]

#MODO OFB - Bloque tamano fijo
ti_OFB=time()
cifrador = AES.new(llave,AES.MODE_OFB,iv)
msgen = cifrador.encrypt(pad(msg))
#print msgen

decipher = AES.new(llave,AES.MODE_OFB,iv)		
unpad(decipher.decrypt(msgen))
tf_OFB=time()
tiempoOFB=tf_OFB-ti_OFB
print 'OFB' ,tiempoOFB
OFB=['OFB' ,tiempoOFB]

#MODO CTR
ti_CTR=time()
ctr =Counter.new(128)
cifrador = AES.new(llave,AES.MODE_CTR,counter =ctr)
msgen=cifrador.encrypt(msg)
#print msgen

decipher = AES.new(llave,AES.MODE_CTR,counter=ctr)		
decipher.decrypt(msgen)
tf_CTR=time()
tiempoCTR=tf_CTR-ti_CTR
print 'CTR' ,tiempoCTR
CTR=['CTR' ,tiempoCTR]

#MODO OPENPGP
ti_OPENPGP=time()
cifrador = AES.new(llave,AES.MODE_OPENPGP,iv)
msgen=cifrador.encrypt(msg)
#print msgen

decipher = AES.new(llave,AES.MODE_OPENPGP,iv)		
decipher.decrypt(msgen)
tf_OPENPGP=time()
tiempoOPENPGP=tf_OPENPGP-ti_OPENPGP
print 'OPENPGP',tiempoOPENPGP
OPENPGP=['OPENPGP',tiempoOPENPGP]

tiempos=[tiempoCBC,tiempoCFB,tiempoCTR,tiempoECB,tiempoOFB,tiempoOPENPGP]
nombres=['CBC','CFB','CTR','ECB','OFB','OPENPGP']
menor=tiempos[0]
indice=0
for valor in tiempos: 
    if valor < menor: 
        menor = valor
        indice=tiempos.index(valor)      
print  nombres[indice] ,menor
