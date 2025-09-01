import base64
import sys
from impacket.dcerpc.v5.dtypes import SID
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.structure import Structure
from impacket.nt_security import SECURITY_DESCRIPTOR


# Replace this with your Base64 blob
base64_blob = """
AQAEgBQAAAAA0AAAAAAAAAFQAAABBBgAAAAAABxUAAAC5VraSkJNUzpWbQVebpT6H9AEAAAEGAAAAAAAHFQAAALlWtpKQk1TOlZtBV5ulPocgAgAAAgDoAAcAAAAAxQAEAAAAAAEA
AAAFCAAAAAAAAADFAAAABAACAMYDAAAAABAgAAAACaAgAAAAMoABAAAABBgAAAAABxUAAAC5VraSkJNUzpWbQVebpT6HAwIAAADA...
""".replace('\n', '').strip()


def parse_sd(blob: bytes):
    sd = SECURITY_DESCRIPTOR(blob)
    print("=== Parsed Security Descriptor ===")
    print(f"Revision: {sd['Revision']}")
    print(f"Control: {sd['Control']}")
    print(f"Owner SID: {SID(sd['OwnerSid'])}")
    print(f"Group SID: {SID(sd['GroupSid'])}")

    dacl = sd['Dacl']
    if dacl is None:
        print("No DACL present.")
        return

    print(f"\nDACL contains {len(dacl.aces)} ACE(s):\n")
    for i, ace in enumerate(dacl.aces):
        sid = SID(ace['Ace']['Sid'])
        access_mask = ace['Ace']['Mask']['Mask']
        ace_type = ace['AceType']
        ace_flags = ace['AceFlags']
        print(f"[{i}] SID: {sid}, AccessMask: 0x{access_mask:08X}, AceType: {ace_type}, AceFlags: {ace_flags}")


def main():
    try:
        binary_blob = base64.b64decode(base64_blob)
        parse_sd(binary_blob)
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
