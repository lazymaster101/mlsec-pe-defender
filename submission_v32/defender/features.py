"""NFS attributes with explicit training/deployment compatibility modes.

The original JSON trainer swaps the names of its DLL/API text fields and pads
those strings. Preserve that training schema; do not 'fix' the learned columns.
"""
import warnings

import lief

lief.logging.disable()
# LIEF warns when it meets an enum value it does not know (e.g. ReadyToRun machine
# codes); _enum_name handles those, so the warning is only log noise.
warnings.filterwarnings('ignore', message=r'.* is not a valid ', category=RuntimeWarning)

OPTIONAL_NUMERIC = (
    'major_image_version', 'minor_image_version', 'major_linker_version',
    'minor_linker_version', 'major_operating_system_version',
    'minor_operating_system_version', 'major_subsystem_version',
    'minor_subsystem_version', 'sizeof_code', 'sizeof_headers', 'sizeof_heap_commit',
)


# .NET ReadyToRun images built for non-Windows hosts store machine = arch XOR an
# OS marker (Apple, Linux, FreeBSD, NetBSD). lief returns those as plain ints, which
# used to crash `.name` and -- via fail-toward-detection -- flag legitimate files.
_R2R_OS_MARKERS = (0x4644, 0x7B79, 0x1993, 0xFD1D)


def _enum_name(value, enum_cls=None) -> str:
    name = getattr(value, 'name', None)
    if isinstance(name, str):
        return name
    raw = int(value)
    if enum_cls is not None:
        for marker in _R2R_OS_MARKERS:
            try:
                return enum_cls(raw ^ marker).name
            except ValueError:
                continue
    return f'UNKNOWN_{raw}'


def extract(bytez: bytes, mode: str = 'training', pe=None) -> dict:
    """pe: optional binary already parsed by the caller (shared parse in the server)."""
    if mode not in ('training', 'legacy'):
        raise ValueError('Unknown feature mode')
    if len(bytez) < 64 or bytez[:2] != b'MZ':
        raise ValueError('Not a PE file')
    if pe is None:
        # bytes avoids the original 2-million-element Python integer list.
        pe = lief.PE.parse(bytez)
    if pe is None:
        raise ValueError('PE parser rejected input')
    header, optional = pe.header, pe.optional_header
    attrs = {name: int(getattr(optional, name)) for name in OPTIONAL_NUMERIC}
    attrs.update(
        virtual_size=int(pe.virtual_size), has_debug=int(pe.has_debug),
        imports=len(pe.imported_functions), exports=len(pe.exported_functions),
        has_relocations=int(pe.has_relocations), has_resources=int(pe.has_resources),
        has_signature=int(pe.has_signatures), has_tls=int(pe.has_tls),
        symbols=len(pe.symbols), timestamp=int(header.time_date_stamps),
        numberof_sections=len(pe.sections),
        machine=_enum_name(header.machine, lief.PE.Header.MACHINE_TYPES),
        magic=_enum_name(optional.magic),
        characteristics_list=' '.join(c.name for c in header.characteristics_list),
        dll_characteristics_list=' '.join(
            name for name, mask in optional.DLL_CHARACTERISTICS.__members__.items()
            if int(optional.dll_characteristics) & int(mask)
        ),
        exports_list=' '.join(f.name[:10000] for f in pe.exported_functions),
    )
    libraries = {}
    for library in pe.imports:
        names = libraries.setdefault(library.name, [])
        for entry in library.entries:
            names.append('ordinal' + str(entry.ordinal) if entry.is_ordinal else entry.name[:10000])
    # Field names intentionally match train_classifier.JSONAttributeExtractor.
    attrs['libraries'] = ' ' + ' '.join(n for ns in libraries.values() for n in ns) + ' '
    attrs['functions'] = ' ' + ' '.join(libraries) + ' '
    if mode == 'legacy':
        attrs.update(
            machine=str(header.machine), imports=len(pe.imports),
            numberof_sections=int(header.numberof_sections),
            libraries=' '.join(i.name for i in pe.imports),
            functions=' '.join(f.name for f in pe.imported_functions),
            exports_list=' '.join(f.name for f in pe.exported_functions),
        )
    return attrs
