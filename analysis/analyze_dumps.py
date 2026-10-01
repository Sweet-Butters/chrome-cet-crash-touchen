r"""Chrome Crashpad 미니덤프에서 충돌 정보를 뽑아 CSV로 정리한다.

사용법: python analyze_dumps.py <덤프 폴더> <출력 CSV>
필요: pip install minidump
덤프 원본은 프로세스 메모리를 담고 있으므로 공개 저장소에 올리지 않는다.
"""
import csv, glob, os, struct, sys, datetime
from minidump.minidumpfile import MinidumpFile

INJECTED = ('tenxw', 'imgsf', 'kos', 'kings', 'nos', 'npk', 'crossex')

def find_module(mods, addr):
    for m in mods:
        if m.baseaddress <= addr < m.baseaddress + m.size:
            return f'{os.path.basename(m.name)}+{addr - m.baseaddress:#x}'
    return None

def region(mf, addr):
    for r in (mf.memory_info.infos if mf.memory_info else []):
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            return f"{getattr(r.Type, 'name', r.Type)}/{getattr(r.AllocationProtect, 'name', hex(r.AllocationProtect) if isinstance(r.AllocationProtect, int) else r.AllocationProtect)}"
    return ''

def main(src, out):
    rows = []
    for f in sorted(glob.glob(os.path.join(src, '*.dmp')), key=os.path.getmtime):
        mf = MinidumpFile.parse(f); rd = mf.get_reader(); mods = mf.modules.modules
        er = mf.exception.exception_records[0]; rec = er.ExceptionRecord
        ctx = next(t for t in mf.threads.threads if t.ThreadId == er.ThreadId).ContextObject
        stack_ret = struct.unpack('<Q', rd.read(ctx.Rsp, 8))[0]
        ssp = rec.ExceptionInformation[1]           # 섀도 스택 포인터
        shadow_ret = struct.unpack('<Q', rd.read(ssp, 8))[0]
        rows.append({
            'dump': os.path.basename(f)[:8],
            'time_kst': datetime.datetime.fromtimestamp(os.path.getmtime(f)).strftime('%Y-%m-%d %H:%M:%S'),
            'exception_code': '0xc0000409',
            'fast_fail_code': rec.ExceptionInformation[0],
            'fault_at': find_module(mods, rec.ExceptionAddress),
            'stack_return': f'{stack_ret:#x}',
            'stack_return_module': find_module(mods, stack_ret) or 'NOT-IN-MODULE',
            'stack_return_region': region(mf, stack_ret),
            'shadow_return': find_module(mods, shadow_ret),
            'injected_modules': ';'.join(sorted({os.path.basename(m.name) for m in mods
                                                  if any(k in m.name.lower() for k in INJECTED)})),
            'module_count': len(mods),
        })
    with open(out, 'w', newline='', encoding='utf-8') as fp:
        w = csv.DictWriter(fp, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(f'{len(rows)} dumps -> {out}')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
