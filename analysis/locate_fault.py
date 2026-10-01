r"""gdi32.dll 안의 충돌 오프셋이 어느 함수의 어느 명령인지 확인한다.

사용법: python locate_fault.py C:\Windows\System32\gdi32.dll 0x4b17
필요: pip install pefile
"""
import sys, pefile

path, rva = sys.argv[1], int(sys.argv[2], 16)
pe = pefile.PE(path)
for f in pe.DIRECTORY_ENTRY_EXCEPTION:          # x64 함수 범위 표(.pdata)
    b, e = f.struct.BeginAddress, f.struct.EndAddress
    if b <= rva < e:
        names = [s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.address == b and s.name]
        print(f'function {names or "?"} range {b:#x}-{e:#x}, offset into function {rva - b:#x}')
img = pe.get_memory_mapped_image()
print('bytes before fault:', img[rva-8:rva].hex(' '))
print('byte at fault     :', img[rva:rva+1].hex(), '(c3 = RET)' if img[rva] == 0xC3 else '')
