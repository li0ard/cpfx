from pygost.asn1schemas.pfx import PFX, OctetStringSafeContents
from pygost.gost341194 import GOST341194
from pygost.gost28147 import cfb_decrypt, ecb_decrypt, DEFAULT_SBOX
import sys, pyderasn, getpass, uuid
from pyderasn import ObjectIdentifier, OctetString, Integer, TagMismatch
from schemas import *
from pygost.kdf import kdf_gostr3411_2012_256
from base64 import standard_b64encode
from textwrap import fill

print("CryptoPro PFX Decoder by li0ard")
passw = getpass.getpass("Введите пароль: ")

def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    if iteration == total: 
        print()

def key2pem(key, oids, algo):
	key = OctetString(key)
	algo = ObjectIdentifier(algo)
	param = ObjectIdentifier(oids[0])
	dgst = ObjectIdentifier(oids[1])

	oids = PKeyOIDs()
	oids["param"] = param
	oids["dgst"] = dgst

	pub = PKeyPub()
	pub["pubalgo"] = ObjectIdentifier(algo)
	pub["params"] = oids

	pkey = PKey()
	pkey["version"] = Integer(0)
	pkey["params"] = pub
	pkey["key"] = key

	return '-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n'.format(fill(standard_b64encode(pkey.encode()).decode("ascii"), 64))

def unwrap_gost(kek, data, sbox=DEFAULT_SBOX):
    if len(data) != 44:
        raise ValueError("Invalid data length")
    ukm, cek_enc, cek_mac = data[:8], data[8:8 + 32], data[-4:]
    cek = ecb_decrypt(kek, cek_enc, sbox=sbox)
    return cek

pfx, tail = PFX().decode(open(sys.argv[1], "rb").read())
_, outer_safe_contents = pfx["authSafe"]["content"].defined
safe_contents, tail = OctetStringSafeContents().decode(bytes(outer_safe_contents[0]["bagValue"]))
shrouded_key_bag, tail = CPKeyBag().decode(bytes(safe_contents[0]["bagValue"]))

salt = bytes(shrouded_key_bag["bagParams"]["params"]["salt"])
iters = int(shrouded_key_bag["bagParams"]["params"]["iters"].tohex(), 16)
keybag = bytes(shrouded_key_bag["bagValue"])

print(" SALT  = " + salt.hex())
print(" ITERS = " + str(iters))

KEY = passw.encode("utf-16le")
count = 1
printProgressBar(0, iters + 1, prefix = 'Прогресс:', suffix = 'Завершено', length = 50, fill="*")
while count < iters + 1:
	KEY = GOST341194(bytes.fromhex(KEY.hex() + salt.hex() +  str(hex(count))[2:].zfill(4))).digest()
	printProgressBar(count + 1, iters + 1, prefix = 'Прогресс:', suffix = 'Завершено', length = 50, fill="*")
	count = count + 1
print(" KEY   = " + KEY.hex())
print(" IV    = " + salt.hex()[:16])
result = cfb_decrypt(KEY, keybag, iv=bytes.fromhex(salt.hex()[:16]))
try:
	result = CPBlob().decode(result)[0]
except TagMismatch as e:
	print("Расшифровка не удалась, скорее всего вы ввели неправильный пароль.\nЕсли вы считаете, что это всё таки ошибка создайте issue на Github")
	quit()
result = bytes(result["value"]).hex()
algtype = result[:32][8:12]
if algtype == "42aa":
	algooid = "1.2.643.7.1.1.1.2"
else:
	algooid = "1.2.643.7.1.1.1.1"
result = CPExportBlob().decode(bytes.fromhex(result[32:]))[0]
ukm = bytes(result["value"]["ukm"]).hex()
cek_enc = bytes(result["value"]["cek"]["enc"]).hex()
cek_mac = bytes(result["value"]["cek"]["mac"]).hex()
oids = (
	result["value"]["oids"]["privateKeyAlgorithm"]["params"]["curve"],
	result["value"]["oids"]["privateKeyAlgorithm"]["params"]["digest"],
)

KEKe = kdf_gostr3411_2012_256(KEY, bytes.fromhex("26bdb878"), bytes.fromhex(ukm))
print(" KEKe  = " + KEKe.hex())

if algtype == "46aa": #256
	print(" ALGO  = ГОСТ Р 34.10-2012 (256 бит)")
	Ks = unwrap_gost(KEKe, bytes.fromhex(ukm + cek_enc + cek_mac))
elif algtype == "42aa": #512
	print(" ALGO  = ГОСТ Р 34.10-2012 (512 бит)")
	cek_enc2 = [cek_enc[i:i+64] for i in range(0,len(cek_enc),64)]
	buff = []
	for i in cek_enc2:
		buff.append(unwrap_gost(KEKe, bytes.fromhex(ukm + i + cek_mac)).hex())
	Ks = bytes.fromhex("".join(buff))
print(" K     = " + Ks.hex())
uid = str(uuid.uuid4())
f = open("exported_" + uid + ".pem", "w")
f.write(key2pem(Ks, oids, algooid))
f.close()
print("Сохранено в exported_" + uid + ".pem")
