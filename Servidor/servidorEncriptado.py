import socket  
import ssl
import seccure
import seguridad
import os
import registros
import sys

privada='02569qwert'
publica= str(seccure.passphrase_to_pubkey(privada))

encriptador = seguridad.Seguridad('23212345123456789123456723212345','qwerty')

s = socket.socket()  
s.bind(("", 9000))
s.listen(100)  
con = 0  
  
while True:  
      try:
            sc, addr = s.accept()
            wrapedSocket =  ssl.wrap_socket(sc, server_side=True, certfile="server.crt", keyfile='server.key')
            con = con+1
            print '\033[1m'+'\033[91m'+'CONEXION #',str(con)+'\033[0m'
            ipValida=False
            print 'IP VALIDA', ipValida
            ipRemota = addr[0]
            print ipRemota
            seccure.decrypt_file('/home/secru/Documentos/Paper/Sockets/Servidor/lista.enc',  '/home/secru/Documentos/Paper/Sockets/Servidor/lista',  privada)
            archivo = open('lista','r')
            for line in archivo.readlines():
                  print 'Leyendo lista blanca'
                  if line.strip() == ipRemota:
                        print 'IP Validada'
                        ipValida=True
                        break
            archivo.close()
            seccure.encrypt_file('/home/secru/Documentos/Paper/Sockets/Servidor/lista',  '/home/secru/Documentos/Paper/Sockets/Servidor/lista.enc', publica)
            os.remove('/home/secru/Documentos/Paper/Sockets/Servidor/lista')
            if ipValida:
                  registros.registrar('Servidor',ipRemota,'Conexion Aceptada')
                  recibido = wrapedSocket.read()  
                  print 'Recibi'
                  split= recibido.split('---')
                  firmaCliente= split[1]
                  print 'FIRMA CLIENTE',firmaCliente
                  cliPublica=split[0]
                  registros.registrar('Servidor',ipRemota,'Clave Publica Recibida')
                  print seccure.verify(cliPublica, firmaCliente, cliPublica)
                  if seccure.verify(cliPublica, firmaCliente, cliPublica):
                        print 'Firma Clave Publica Verificada'
                        registros.registrar('Servidor',ipRemota,'Firma Clave Publica Verificada')
                        llaves = encriptador.llaveAES+'---'+encriptador.llaveMAC
                        print llaves
                        firma = seccure.sign(llaves, privada) 
                        print firma
                        wrapedSocket.write(firma+'---'+llaves)
                        registros.registrar('Servidor',ipRemota,'Claves Enviadas')
                        print 'Envie firma'
                        rec= wrapedSocket.read()
                        print rec
                        splitRec=rec.split('---')
                        signCliente = splitRec[0]
                        msjEncriptado = splitRec[1]
                        macEnviado = splitRec[2]
                        registros.registrar('Servidor',ipRemota,'Mensaje Encriptado Recibido')
                        if seccure.verify(splitRec[1]+'---'+splitRec[2],signCliente,cliPublica):
                              print 'SE HA VERIFICADO EL SEGUNDO MENSAJE DEL CLIENTE'
                              registros.registrar('Servidor',ipRemota,'Firma Mensaje Verificada')
                              if encriptador.compararMAC(msjEncriptado, macEnviado):
                                    msjPlano = encriptador.desencriptar(msjEncriptado)
                                    registros.registrar('Servidor',ipRemota,'MAC verificado y mensaje desencriptado')
                                    print msjPlano
                              else:
                                    print 'EL MAC HA SIDO MODIFICADO'
                                    registros.registrar('Servidor',ipRemota,'MAC ha sido modificado - Integridad Violada')
                        else:
                              registros.registrar('Servidor',ipRemota,'Firma Mensaje INVALIDA')
                              wrapedSocket.close()
                              sc.close()      
                  else:
                        registros.registrar('Servidor',ipRemota,'Firma Clave Publica INVALIDA')
                        wrapedSocket.close()
                        sc.close()
        
                  print "Recibido:", recibido, addr
            else:
                  print 'LA DIRECCION IP NO HA SIDO VALIDADA'
                  registros.registrar('Servidor',ipRemota,'Conexion Rechazada')
                  print 'Conexion Cerrada con '+ ipRemota
                  wrapedSocket.close()
                  sc.close()
      except:
            registros.registrar('Servidor',ipRemota,str(sys.exc_info()[0]))
            wrapedSocket.close()
            sc.close() 
            s.close() 
            raise            
  
print "Adios"  
  
wrapedSocket.close()
sc.close()  
s.close() 