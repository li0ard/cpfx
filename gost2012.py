import sys, getpass
from pyasn1.codec.der import decoder
from pygost.kdf import kdf_gostr3411_2012_256
from pyasn1_modules import rfc2315
from pyasn1_modules.rfc7292 import AuthenticatedSafe, PFX
from pygost.gost341194 import GOST341194
from pygost.gost28147 import DEFAULT_SBOX
from pygost.gost28147 import ecb_decrypt
from pygost.gost28147 import cfb_decrypt
import asn1
from pyasn1.codec.der.encoder import encode
import pyasn1
import base64

print("CryptoPro PFX Decoder by li0ard")
passw = getpass.getpass("Введите пароль: ")

def _decode(content, asn1Spec=None, decoder=decoder):
	decoded_obj, remaining = decoder.decode(content, asn1Spec=asn1Spec)
	return decoded_obj

def getOids(hexstr):
# Получение оидов набора параметров и алгоритма хэша, пришлось сделать вот такой говнокод ибо pyasn1 не видит оиды
	decoder = asn1.Decoder()
	decoder.start(hexstr)
	tag, value = decoder.read()
	decoder.start(value)
	tag, value = decoder.read()
	decoder.start(value)
	tag, value = decoder.read()
	tag, value = decoder.read()
	tag, value = decoder.read()
	decoder.start(value)
	tag, value = decoder.read()
	tag, value = decoder.read()
	decoder.start(value)
	tag, value = decoder.read()
	algo = value
	tag, value = decoder.read()
	decoder.start(value)
	tag, value = decoder.read()
	params = value
	tag, value = decoder.read()
	dgst = value
	return (algo, params, dgst)

def encodeKey(key, oids, algo="1.2.643.7.1.1.1.1"):
	algo = pyasn1.type.univ.ObjectIdentifier(algo)
	params = pyasn1.type.univ.ObjectIdentifier(oids[1])
	dgst = pyasn1.type.univ.ObjectIdentifier(oids[2])

	seq = pyasn1.type.univ.Sequence()
	seq.setComponents(params, dgst)

	seq2 = pyasn1.type.univ.Sequence()
	seq2.setComponents(algo, seq)

	seq3 = pyasn1.type.univ.Sequence()
	seq3.setComponents(
		pyasn1.type.univ.Integer(0),
		seq2,
		pyasn1.type.univ.OctetString(bytes.fromhex(key))
	)
	return '-----BEGIN PRIVATE KEY-----\n{}-----END PRIVATE KEY-----\n'.format(base64.encodestring(encode(seq3)).decode("ascii"))

def unwrap_gost(kek, data, sbox=DEFAULT_SBOX):
    if len(data) != 44:
        raise ValueError("Invalid data length")
    ukm, cek_enc, cek_mac = data[:8], data[8:8 + 32], data[-4:]
    cek = ecb_decrypt(kek, cek_enc, sbox=sbox)
    # Проверка убрана так как выдает ошибку на 512 битах
    """if MAC(kek, data=cek, iv=ukm, sbox=sbox).digest()[:4] != cek_mac:
        raise ValueError("Invalid MAC")"""
    return cek

def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    if iteration == total: 
        print()

decode = decoder.decode(open(sys.argv[1], "rb").read(), asn1Spec=PFX())[0]
if decode['authSafe']['contentType'] == rfc2315.data: 
	auth_safe = _decode(_decode(decode['authSafe']['content'].asOctets()).asOctets(), asn1Spec=AuthenticatedSafe())
	content = _decode(auth_safe[0]['content'].asOctets(), asn1Spec=rfc2315.Data())
	content = _decode(content.asOctets())[0][1]
	salt = content[0][1][0].asOctets().hex()
	iters = content[0][1][1]
	keybag = content[1].asOctets().hex()
	print("SALT  = " + salt)
	print("ITERS = " + str(iters))
	SALT1 = bytes.fromhex(salt)
	KEY = passw.encode("utf-16le")
	count = 1
	print("[-] Вычисляю ключ для транспортной кодировки..")
	printProgressBar(0, iters + 1, prefix = 'Прогресс:', suffix = 'Завершено', length = 50, fill="*")
	while count < iters + 1:
		KEY = GOST341194(bytes.fromhex(KEY.hex() + salt +  str(hex(count))[2:].zfill(4))).digest()
		printProgressBar(count + 1, iters + 1, prefix = 'Прогресс:', suffix = 'Завершено', length = 50, fill="*")
		count = count + 1
	print(" KEY  = " + KEY.hex())
	print(" IV   = " + salt[:16])
	print("[-] Снимаю транспортную кодировку..")
	result = ""
	try:
		result = cfb_decrypt(KEY, bytes.fromhex(keybag), iv=bytes.fromhex(salt[:16])).hex()
	except Exception as e:
		print("[!] Произошла ошибка (Транспортная кодировка)")
		quit()
	print("[-] Транспортная кодировка снята")
	content = _decode(bytes.fromhex(result))[2].asOctets().hex()
	print("[-] Получены данные ключа..")
	algtype = content[:32][8:12] # Данные блоба криптопро
	if algtype == "42aa": # 512 бит
		algooid = "1.2.643.7.1.1.1.2"
	else:
		algooid = "1.2.643.7.1.1.1.1"
	#print(content[32:])
	keyblob = _decode(bytes.fromhex(content[32:]))
	ukm = keyblob[0][0].asOctets().hex()
	cek_enc = keyblob[0][1][0].asOctets().hex()
	cek_mac = keyblob[0][1][1].asOctets().hex()
	print(" UKM  = " + ukm)
	print(" ENC  = " + cek_enc)
	print(" MAC  = " + cek_mac)
	print("[-] Снимаю экспортную кодировку..")
	KEKe = kdf_gostr3411_2012_256(KEY, bytes.fromhex("26bdb878"), bytes.fromhex(ukm))
	print(" KEKe = " + KEKe.hex())
	if algtype == "46aa": #256
		Ks = unwrap_gost(KEKe, bytes.fromhex(ukm + cek_enc + cek_mac))
	elif algtype == "42aa": #512
		cek_enc2 = [cek_enc[i:i+64] for i in range(0,len(cek_enc),64)]
		buff = []
		for i in cek_enc2:
			buff.append(unwrap_gost(KEKe, bytes.fromhex(ukm + i + cek_mac)).hex())
		Ks = bytes.fromhex("".join(buff))
	print("[-] Экспортная кодировка снята")
	print(" K    = " + Ks.hex())
	# Запись ключа
	print("[-] Кодирую ключ в PEM")
	print(encodeKey(Ks.hex(), getOids(bytes.fromhex(content[32:])), algooid))
