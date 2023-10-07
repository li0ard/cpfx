from pyderasn import Sequence, OctetString, ObjectIdentifier, Any, Integer
class CPParamsValue(Sequence):
	schema = (
		("salt", OctetString()),
		("iters", Integer())
	)

class CPParams(Sequence):
	schema = (
		("algo", ObjectIdentifier()),
		("params", CPParamsValue())
	)

class CPKeyBag(Sequence):
	schema = (
		("bagParams", CPParams()),
		("bagValue", OctetString())
	)

class CPBlob(Sequence):
	schema = (
		("version", Integer()),
		("notused", Any()),
		("value", OctetString()),
		("notused2", Any(optional=True))
	)

class CPExportBlobCek(Sequence):
	schema = (
		("enc", OctetString()),
		("mac", OctetString())
	)

class CPExportBlob2(Sequence):
	schema = (
		("ukm", OctetString()),
		("cek", CPExportBlobCek()),
		("oids", Any())
	)

class CPExportBlob(Sequence):
	schema = (
		("value", CPExportBlob2()),
		("notused", OctetString())
	)

class PKeyOIDs(Sequence):
	schema = (
		("param", ObjectIdentifier()),
		("dgst", ObjectIdentifier())
	)

class PKeyPub(Sequence):
	schema = (
		("pubalgo", ObjectIdentifier()),
		("params", PKeyOIDs())
	)

class PKey(Sequence):
	schema = (
		("version", Integer(0)),
		("params", PKeyPub()),
		("key", OctetString())
	)
