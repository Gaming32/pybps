import io
import os
import zlib
from typing import BinaryIO, Optional, Union

MAGIC = b'BPS1'
_BUFFER_SIZE = 8192
_EMPTY_DATA = bytes(_BUFFER_SIZE)


class BPSError(ValueError):
    pass


class InvalidFormatError(BPSError):
    pass


class ChecksumFailure(BPSError):
    pass


class _ReadState:
    buffer: BinaryIO
    position: int
    checksum: int

    def __init__(self, buffer: BinaryIO) -> None:
        self.buffer = buffer
        self.position = 0
        self.checksum = 0

    def read(self, n: int = 1) -> bytes:
        data = self.buffer.read(n)
        self.position += len(data) # May be smaller than n
        self.checksum = zlib.crc32(data, self.checksum) & 0xffffffff
        return data

    def write(self, data: bytes) -> None:
        self.buffer.write(data)
        self.position += len(data)
        self.checksum = zlib.crc32(data, self.checksum) & 0xffffffff


class _PatchState:
    source: _ReadState
    patch: _ReadState
    target: _ReadState

    def __init__(self, source: BinaryIO, patch: BinaryIO, target: BinaryIO) -> None:
        self.source = _ReadState(source)
        self.patch = _ReadState(patch)
        self.target = _ReadState(target)


_Readable = Union[_ReadState, BinaryIO]


class PatchResult:
    source_size: int
    target_size: int
    metadata: bytes
    source_checksum: int
    target_checksum: int
    patch_checksum: int


def _decode_number(input: _Readable) -> int:
    data = 0
    shift = 1
    while True:
        x = input.read(1)[0]
        data += (x & 0x7f) * shift
        if x & 0x80:
            break
        shift <<= 7
        data += shift
    return data


def _buffered_copy(source: _Readable, target: _Readable, length: int, buffer_size: int = _BUFFER_SIZE) -> None:
    while length > 0:
        buffer = source.read(min(length, buffer_size))
        target.write(buffer)
        length -= buffer_size


def dis(
        patch: BinaryIO,
        patch_size: int
    ) -> None:
    reader = _ReadState(patch)

    print('string         ', reader.read(4))
    source_size = _decode_number(reader)
    print('source-size    ', source_size)
    target_size = _decode_number(reader)
    print('target-size    ', target_size)
    metadata_size = _decode_number(reader)
    print('metadata-size  ', metadata_size)
    metadata = reader.read(metadata_size)
    print('metadata       ', metadata)

    patch_end = patch_size - 12
    print('repeat')
    while reader.position < patch_end:
        data = _decode_number(reader)
        command = data & 3
        length = (data >> 2) + 1
        if command == 0:
            print('   SourceRead', length)
        elif command == 1:
            print('   TargetRead', length, reader.read(length))
        elif command == 2:
            data = _decode_number(reader)
            print('   SourceCopy', (-1 if (data & 1) else 1) * (data >> 1))
        elif command == 3:
            data = _decode_number(reader)
            print('   TargetCopy', (-1 if (data & 1) else 1) * (data >> 1))
        else:
            raise InvalidFormatError(f'Invalid command {command} (expected 0, 1, 2, or 3)')

    source_checksum = int.from_bytes(reader.read(4), 'little', signed=False)
    print(f'source-checksum {source_checksum:x}')
    target_checksum = int.from_bytes(reader.read(4), 'little', signed=False)
    print(f'target-checksum {target_checksum:x}')
    patch_checksum = int.from_bytes(patch.read(4), 'little', signed=False)
    print(f'patch-checksum  {patch_checksum:x}')


def _patch(
        source_abs: BinaryIO,
        source_rel: BinaryIO,
        patch: BinaryIO,
        patch_size: int,
        target_abs: BinaryIO,
        target_rel: BinaryIO,
        skip_checksum: bool = False
    ) -> PatchResult:
    """Returns the metadata string (may be empty)"""
    state = _PatchState(source_abs, patch, target_abs)

    if (magic := state.patch.read(4)) != MAGIC:
        raise InvalidFormatError(f'File magic {magic} != {MAGIC}')
    source_size = _decode_number(state.patch)
    target_size = _decode_number(state.patch)
    metadata_size = _decode_number(state.patch)
    metadata = state.patch.read(metadata_size)

    target_rel_base = target_rel.tell()

    patch_end = patch_size - 12
    while state.patch.position < patch_end:
        data = _decode_number(state.patch)
        command = data & 3
        length = (data >> 2) + 1
        if command == 0:
            _buffered_copy(state.source, state.target, length)
        elif command == 1:
            _buffered_copy(state.patch, state.target, length)
        elif command == 2:
            data = _decode_number(state.patch)
            source_rel.seek((-1 if (data & 1) else 1) * (data >> 1), io.SEEK_CUR)
            _buffered_copy(source_rel, state.target, length)
        elif command == 3:
            data = _decode_number(state.patch)
            target_rel.seek((-1 if (data & 1) else 1) * (data >> 1), io.SEEK_CUR)
            target_rel_offset = target_rel.tell() - target_rel_base
            # Data can be buffered, instead of copied byte by byte
            if state.target.position - 8 > target_rel_offset:
                _buffered_copy(target_rel, state.target, length, min(state.target.position - target_rel_offset, _BUFFER_SIZE))
            else:
                for _ in range(length):
                    state.target.write(target_rel.read(1))
        else:
            raise InvalidFormatError(f'Invalid command {command} (expected 0, 1, 2, or 3)')
        print(state.target.position)

    # Make sure we calculate the full checksums!
    while state.source.position < source_size:
        remaining = source_size - state.source.position
        while remaining > 0:
            state.source.read(min(remaining, _BUFFER_SIZE)) # Don't read past end
            remaining -= _BUFFER_SIZE
    while state.target.position < target_size:
        remaining = target_size - state.target.position
        while remaining > 0:
            state.target.write(_EMPTY_DATA[:min(remaining, _BUFFER_SIZE)])
            remaining -= _BUFFER_SIZE

    source_checksum = int.from_bytes(state.patch.read(4), 'little', signed=False)
    if not skip_checksum and state.source.checksum != source_checksum:
        raise ChecksumFailure(f'Source checksum {state.source.checksum:x} != {source_checksum:x}')
    target_checksum = int.from_bytes(state.patch.read(4), 'little', signed=False)
    if not skip_checksum and state.target.checksum != target_checksum:
        raise ChecksumFailure(f'Source checksum {state.target.checksum:x} != {target_checksum:x}')
    patch_checksum = int.from_bytes(patch.read(4), 'little', signed=False)
    if not skip_checksum and state.patch.checksum != patch_checksum:
        raise ChecksumFailure(f'Source checksum {state.patch.checksum:x} != {patch_checksum:x}')

    result = PatchResult()
    result.source_size = source_size
    result.target_size = target_size
    result.metadata = metadata
    result.source_checksum = source_checksum
    result.target_checksum = target_checksum
    result.patch_checksum = patch_checksum
    return result


_MustBeOpened = (str, bytes, os.PathLike)
_File = Union[str, bytes, os.PathLike[str], os.PathLike[bytes], BinaryIO]


def patch(
        source: _File,
        patch: _File,
        target: _File,
        patch_size: Optional[int] = None,
        skip_checksum: bool = False
    ) -> PatchResult:
    if isinstance(source, _MustBeOpened):
        source_abs = open(source, 'rb')
        source_rel = open(source, 'rb')
    else:
        raise ValueError('source must be file path')

    if isinstance(patch, _MustBeOpened):
        patch = open(patch, 'rb')
    if patch_size is None:
        cur = patch.tell()
        patch.seek(0, io.SEEK_END)
        patch_size = patch.tell()
        patch.seek(cur, io.SEEK_SET)

    if isinstance(target, _MustBeOpened):
        target_abs = open(target, 'wb', buffering=0)
        target_rel = open(target, 'rb')
    else:
        raise ValueError('target must be file path')

    return _patch(
        source_abs,
        source_rel,
        patch,
        patch_size,
        target_abs,
        target_rel,
        skip_checksum
    )


if __name__ == '__main__':
    # patch(
    #     'input.json',
    #     'patch.bps',
    #     'result.json'
    # )
    # dis(open('pypatch.bps', 'rb'), 24823)
    # patch(
    #     'input.py',
    #     'pypatch.bps',
    #     'result.py'
    # )
    # patch(
    #     r"C:\Users\josia\MEGA\Projects\Downloadables\Super Mario 64.z64",
    #     r"C:\Users\josia\MEGA\Projects\SM64 Hacks\XMas mini\XMas.bps",
    #     'result.z64'
    # )
    import sys
    if len(sys.argv) < 2 or sys.argv[1] not in ('patch', 'dis'):
        print('Usage: pybps.py <patch|dis> ...')
    if sys.argv[1] == 'patch':
        if len(sys.argv) < 5:
            print('Usage: pybps.py patch <source> <patch> <target>')
        patch(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == 'dis':
        if len(sys.argv) < 3:
            print('Usage: pybps.py patch <patch>')
        with open(sys.argv[1], 'rb') as fp:
            size = fp.seek(0, io.SEEK_END)
            fp.seek(0, io.SEEK_SET)
            dis(fp, size)
