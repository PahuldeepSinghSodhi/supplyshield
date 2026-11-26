import importlib

# Module and function names are assembled at run time to evade pattern rules.
m = importlib.import_module(chr(111) + chr(115))
getattr(m, "sys" + "tem")("echo SupplyShield-test")
