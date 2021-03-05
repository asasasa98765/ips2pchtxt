from struct import *

infile = '034C8FA7A63B7A87F96F408B2AEFFF6C.ips'
outfile = 'output.pchtxt'

f = open(infile, mode='rb')
ips32 = f.read(5)

if ips32 == b'IPS32':
  txt = open(outfile, mode='w')
  txt.write('@nsobid-034C8FA7A63B7A87F96F408B2AEFFF6C\n')
  txt.write('@flag offset_shift 0x100\n')
  txt.write('\n')
  while True:
  	address = f.read(4)
  	if address == b'EEOF':
  	  break
  	if len(address) == 0:
  	  break
  	size = f.read(2)
  	patch = f.read(int.from_bytes(size, byteorder='big'))
  	addr = address.hex()
  	addr = format(int(addr,16) - 256,'x')
  	print((addr.upper()).zfill(8) + ' ' + (patch.hex()).upper())
  	txt.write((addr.upper()).zfill(8) + ' ' + (patch.hex().upper()) + '\n')

f.close()
txt.close()