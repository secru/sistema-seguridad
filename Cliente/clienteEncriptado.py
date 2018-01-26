import socket  
import ssl
import seccure
import seguridad
import registros
import sys
  
publicaServer= '/dTH4?T]2K1WrB%CeYujd4I?{'
privada='uoi1243i4231'
publica= str(seccure.passphrase_to_pubkey(privada)) 

s = socket.socket()   
ipServidor = 'localhost' 
wrapedSocket=ssl.wrap_socket(s, ca_certs="server.crt", cert_reqs=ssl.CERT_REQUIRED)  
wrapedSocket.connect((ipServidor, 9000)) 
registros.registrar('Cliente',ipServidor,'Conectado con el servidor')

while True:
      try:
            firma = seccure.sign(publica, privada) 
            wrapedSocket.write(publica+'---'+firma)
            registros.registrar('Cliente',ipServidor,'Clave Publica Enviada')
            datos = wrapedSocket.read()
            split = datos.split('---')
            firmaServer = split[0]
            cAES = split[1]
            cMAC = split[2]
            msjServer=cAES+'---'+cMAC
            registros.registrar('Cliente',ipServidor,'Claves recibidas')
            if seccure.verify(msjServer, firmaServer, publicaServer):
                  registros.registrar('Cliente',ipServidor,'Firma Claves Verificada')
                  print 'verificada la firma de server'
                  msj = 'ESTE ES EL MENSAJE QUE SE DESEA ENVIAR ENCRIPTADO'
                  encriptador = seguridad.Seguridad(cAES,cMAC)
                  msgencrip=encriptador.encriptar(msj)
                  macenviado = encriptador.generarMAC(msgencrip)
                  firmaMsj = seccure.sign(msgencrip+'---'+macenviado,privada)
                  print firmaMsj
                  wrapedSocket.write(firmaMsj+'---'+msgencrip+'---'+macenviado)
                  registros.registrar('Cliente',ipServidor,'Mensaje Encriptado Enviado')
            else:
                  registros.registrar('Cliente',ipServidor,'Firma Claves INVALIDA')
                  wrapedSocket.close()

            mensaje = raw_input("> ")
            break
      except:
            registros.registrar('Cliente',ipServidor,str(sys.exc_info()[0]))
            print 'Conexion Cerrada'
            wrapedSocket.close() 
            s.close() 
            raise 
print "Adios"  

wrapedSocket.close()
s.close() 