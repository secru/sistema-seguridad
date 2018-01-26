import logging

def registrar(nombre,ip,estado):
    logging.basicConfig(filename=nombre+'.log',level=logging.DEBUG,format='%(asctime)s %(message)s', datefmt='%d/%m/%Y %I:%M:%S %p')
    logging.info('Intento ' +ip+' '+estado)