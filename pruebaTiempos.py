from time import time
from Crypto.Cipher import AES
from Crypto.Util import Counter

base = 16
pad = lambda s: s + (base - len(s) % base) * chr(base - len(s) % base)
unpad = lambda s : s[0:-ord(s[-1])]

llave= '23212345123456789123456723212345'
iv = '123456789abcdefg'

msg = 'P'
tmMsg = 1024 *100
#msg=msg.zfill(tmMsg)
print msg

#MODO ECB - Bloque tamano fijo
tic_ECB=time()
cifrador = AES.new(llave,AES.MODE_ECB)
msgen = cifrador.encrypt(pad(msg))
tfc_ECB=time()
tiempocECB=tfc_ECB-tic_ECB
#print msgen

ti_ECB=time()
decipher = AES.new(llave,AES.MODE_ECB)	
unpad(decipher.decrypt(msgen))
tf_ECB=time()
tiempodECB=tf_ECB-ti_ECB
print 'ECB' ,'Cifrado:',tiempocECB ,'Tiempo:', (len(msg))/(tiempocECB), 'Bytes/s'
print 'ECB' ,'Descifrado:',tiempodECB ,'Tiempo:', (len(msg))/(tiempodECB), 'Bytes/s'

#MODO CFB
tic_CFB=time()
cifrador = AES.new(llave,AES.MODE_CFB,iv)
msgen=cifrador.encrypt(msg)
tfc_CFB=time()
tiempocCFB=tfc_CFB-tic_CFB
#print msgen

tid_CFB=time()
decipher = AES.new(llave,AES.MODE_CFB,iv)		
decipher.decrypt(msgen)
tfd_CFB=time()
tiempodCFB=tfd_CFB-tid_CFB
print 'CFB Cifrado' , tiempocCFB,'Tiempo:', (len(msg))/(tiempocCFB), 'Bytes/s'
print 'CFB Descifrado' , tiempodCFB,'Tiempo:', (len(msg))/(tiempodCFB), 'Bytes/s'

#MODO CBC - Bloque tamano fijo
tic_CBC=time()
cifrador = AES.new(llave,AES.MODE_CBC,iv)
msgen=cifrador.encrypt(pad(msg))
tfc_CBC=time()
tiempocCBC=tfc_CBC-tic_CBC
#print msgen

tid_CBC=time()
decipher = AES.new(llave,AES.MODE_CBC,iv)		
unpad(decipher.decrypt(msgen))
tfd_CBC=time()
tiempodCBC=tfd_CBC-tid_CBC
print 'CBC Cifrado' ,tiempocCBC,'Tiempo:', (len(msg))/(tiempocCBC), 'Bytes/s'
print 'CBC Descifrado' ,tiempodCBC,'Tiempo:', (len(msg))/(tiempodCBC), 'Bytes/s'

#MODO OFB - Bloque tamano fijo
tic_OFB=time()
cifrador = AES.new(llave,AES.MODE_OFB,iv)
msgen = cifrador.encrypt(pad(msg))
tfc_OFB=time()
tiempocOFB=tfc_OFB-tic_OFB
#print msgen

tid_OFB=time()
decipher = AES.new(llave,AES.MODE_OFB,iv)		
unpad(decipher.decrypt(msgen))
tfd_OFB=time()
tiempodOFB=tfd_OFB-tid_OFB
print 'OFB Cifrado' ,tiempocOFB,'Tiempo:', (len(msg))/(tiempocOFB), 'Bytes/s'
print 'OFB Descifrado' ,tiempodOFB,'Tiempo:', (len(msg))/(tiempodOFB), 'Bytes/s'

#MODO CTR
tic_CTR=time()
ctr =Counter.new(128)
cifrador = AES.new(llave,AES.MODE_CTR,counter =ctr)
msgen=cifrador.encrypt(msg)
tfc_CTR=time()
tiempocCTR=tfc_CTR-tic_CTR
#print msgen

tid_CTR=time()
decipher = AES.new(llave,AES.MODE_CTR,counter=ctr)		
decipher.decrypt(msgen)
tfd_CTR=time()
tiempodCTR=tfd_CTR-tid_CTR
print 'CTR Cifrado' ,tiempocCTR,'Tiempo:', (len(msg))/(tiempocCTR), 'Bytes/s'
print 'CTR Descifrado' ,tiempodCTR,'Tiempo:', (len(msg))/(tiempodCTR), 'Bytes/s'

#MODO OPENPGP
tic_OPENPGP=time()
cifrador = AES.new(llave,AES.MODE_OPENPGP,iv)
msgen=cifrador.encrypt(msg)
tfc_OPENPGP=time()
tiempocOPENPGP=tfc_OPENPGP-tic_OPENPGP
#print msgen

tid_OPENPGP=time()
decipher = AES.new(llave,AES.MODE_OPENPGP,iv)		
decipher.decrypt(msgen)
tfd_OPENPGP=time()
tiempodOPENPGP=tfd_OPENPGP-tid_OPENPGP
print 'OPENPGP Cifrado',tiempocOPENPGP,'Tiempo:', (len(msg))/(tiempocOPENPGP), 'Bytes/s'
print 'OPENPGP Descifrado',tiempodOPENPGP,'Tiempo:', (len(msg))/(tiempodOPENPGP), 'Bytes/s'

tiemposc=[tiempocCBC,tiempocCFB,tiempocCTR,tiempocECB,tiempocOFB,tiempocOPENPGP]
tiemposd=[tiempodCBC,tiempodCFB,tiempodCTR,tiempodECB,tiempodOFB,tiempodOPENPGP]
nombres=['CBC','CFB','CTR','ECB','OFB','OPENPGP']
menor=tiemposc[0]
indice=0
for valor in tiemposc: 
    if valor < menor: 
        menor = valor
        indice=tiemposc.index(valor)      
print  nombres[indice] ,menor
menores=tiemposd[0]
indices=0
for valores in tiemposd: 
    if valores < menor: 
        menores = valores
        indices=tiemposd.index(valores)      
print  nombres[indices] ,menores