import struct
from math import ceil
import collections

# We need 32 bits for envelope and 64 bits for the data.
# Just use bitshifts for everything else.
decode_int32 = struct.Struct('<I').unpack
encode_int32 = struct.Struct('<I').pack
decode_int64 = struct.Struct('<Q').unpack
encode_int64 = struct.Struct('<Q').pack


def decode_bits(i, first, last):
    return (i & ((1 << (last+1)) - (1 << first))) >> first

def decode_segments(message):
    seg_count = decode_int32(message[:4])[0] + 1
    segments = []
    start = ceil((seg_count+1)/2.) * 8
    for i in range(seg_count):
        segment_length, = decode_int32(message[i*4:i*4+4])
        segments.append([decode_int64(message[start+i*8:start+i*8+8])[0] for i in range(segment_length)])
        start += segment_length * 8
    assert start == len(message)
    return segments

def read_segments(stream):
    data = stream.read(4)
    if data == '':
        return None
    seg_count = decode_int32(data)[0] + 1
    segment_lengths = []
    for i in range(seg_count):
        segment_lengths.append(decode_int32(stream.read(4))[0])
    if seg_count % 2 == 0:
        stream.read(4)
    segments = []
    for segment_length in segment_lengths:
        segments.append([decode_int64(stream.read(8))[0] for i in range(segment_length)])
    return segments

def read_messages(stream):
    while True:
        segments = read_segments(stream)
        if segments is None:
            break
        yield segments

def encode_segments(segments):
    if len(segments) % 2 == 0:
        pad = encode_int32(0)
    else:
        pad = b''
    return encode_int32(len(segments)-1) + b''.join(encode_int32(len(segment)) for segment in segments) + pad + b''.join(encode_int64(x) for segment in segments for x in segment)

SPECIAL_POINTER = (1 << 32) - 4

class MessageRef(collections.namedtuple('MessageRefBase', 'segments current_seg current_offset zero_always_minus_one')):
    def follow_pointer(self):
        ptr_data = self.as_integer()
        if ptr_data == 0:
            return Null(self)
        ptr_type = decode_bits(ptr_data, 0, 1)
        if ptr_type == 0:
            offset = decode_bits(ptr_data, 2, 31)
            data_len = decode_bits(ptr_data, 32, 47)
            pointer_len = decode_bits(ptr_data, 48, 63)
            new_ref = self.relative_offset(offset+1)
            return Struct(data_len, pointer_len, new_ref)
        elif ptr_type == 1:
            offset = decode_bits(ptr_data, 2, 31)
            data_type = decode_bits(ptr_data, 32, 34)
            reported_size = decode_bits(ptr_data, 35, 63)
            new_ref = self.relative_offset(offset+1)
            if data_type < 6:
                return IntList(data_type, reported_size, new_ref)
            if data_type == 6:
                return PointerList(reported_size, new_ref)
            tag_data = new_ref.as_integer()
            size = decode_bits(tag_data, 2, 31)
            data_len = decode_bits(tag_data, 32, 47)
            pointer_len = decode_bits(tag_data, 48, 63)
            assert reported_size == (data_len + pointer_len) * size, (size, reported_size)
            data_ref = new_ref.relative_offset(1)
            return StructList(data_len, pointer_len, size, data_ref)
        elif ptr_type == 2:
            far_type = decode_bits(ptr_data, 2, 2)
            offset = decode_bits(ptr_data, 3, 31)
            segment = decode_bits(ptr_data, 32, 63)
            pad = self._replace(current_seg=segment, current_offset=offset)
            if far_type == 0:
                return pad.follow_pointer()
            # pad is another far pointer
            # reinterpret pad[1] to start at dest(pad[0])
            ptr_data = pad.as_integer()
            # We're not allowed a far pointer here.
            assert decode_bits(ptr_data, 2, 2) == 0
            offset = decode_bits(ptr_data, 3, 31)
            segment = decode_bits(ptr_data, 32, 63)
            obj = pad.relative_offset(1).follow_pointer()
            # Make sure we followed a pointer of offset zero.
            # TODO This will be broken for far pointers of this type to a struct list.
            assert obj.message_ref.current_offset == pad.current_offset + 2 and obj.message_ref.current_seg == pad.current_seg
            obj.message_ref = self._replace(current_seg=segment, current_offset=offset)
            return obj
        elif ptr_type == 3:
            other_ptr_type = decode_bits(ptr_data, 2, 32)
            assert other_ptr_type == 0
            capability_index = decode_bits(ptr_data, 33, 64)
            return Capability(capability_index, self)

    def relative_offset(self, offset):
        return self._replace(current_offset=self.current_offset + offset)

    def as_integer(self):
        return self.segments[self.current_seg][self.current_offset]

    def set_integer(self, i):
        self.segments[self.current_seg][self.current_offset] = i

    def set_pointer(self, pointer_data, pointer_to):
        if pointer_data == 0 and (self.zero_always_minus_one or pointer_to.current_offset == self.current_offset + 1):
            # We don't want to encode a non-null pointer to equal zero.
            # So we set the offset to -1, which is always in-bounds!
            pointer_value = SPECIAL_POINTER
        else:
            assert pointer_to.current_seg == self.current_seg
            pointer_value = pointer_data + ((pointer_to.current_offset - self.current_offset - 1) << 2)
        self.set_integer(pointer_value)

    def extend_segment(self, size):
        old_end = len(self.segments[self.current_seg])
        self.segments[self.current_seg] += [0] * size
        return self._replace(current_offset=old_end)

class Null(object):
    def __init__(self, message_ref):
        self.message_ref = message_ref

    def canonical_pointer(self, new_ref):
        return

class Struct(object):
    def __init__(self, data_len, pointer_len, message_ref):
        assert isinstance(message_ref, MessageRef), message_ref
        self.data_len = data_len
        self.pointer_len = pointer_len
        self.message_ref = message_ref

    def min_data_len(self):
        m = i = 0
        while i < self.data_len:
            if self.message_ref.relative_offset(i).as_integer() != 0:
                m = i + 1
            i += 1
        return m

    def min_pointer_len(self):
        m = i = 0
        while i < self.pointer_len:
            if self.message_ref.relative_offset(i+self.data_len).as_integer() != 0:
                m = i + 1
            i += 1
        return m

    def canonical_pointer(self, new_ref):
        data_len = self.min_data_len()
        pointer_len = self.min_pointer_len()
        pointer_data = 0 + (data_len << 32) + (pointer_len << 48)
        data_ref = new_ref.extend_segment(data_len+pointer_len)
        new_ref.set_pointer(pointer_data, data_ref)
        self.canonical_encode(data_ref, data_len, pointer_len)

    def canonical_encode(self, data_ref, data_len, pointer_len):
        for i in range(data_len):
            data_ref.relative_offset(i).set_integer(self.message_ref.relative_offset(i).as_integer())
        pointer_ref = data_ref.relative_offset(data_len)
        my_pointer_ref = self.message_ref.relative_offset(self.data_len)
        for i in range(pointer_len):
            my_pointer_ref.relative_offset(i).follow_pointer().canonical_pointer(pointer_ref.relative_offset(i))

class StructList(object):
    def __init__(self, data_len, pointer_len, size, message_ref):
        # message_ref is after tag.
        self.data_len = data_len
        self.pointer_len = pointer_len
        self.size = size
        self.message_ref = message_ref

    def min_member_data_len(self):
        if self.size == 0:
            return 0
        return max(s.min_data_len() for s in self)

    def min_member_pointer_len(self):
        if self.size == 0:
            return 0
        return max(s.min_pointer_len() for s in self)

    def __iter__(self):
        word_size = self.data_len + self.pointer_len
        for i in range(self.size):
            yield Struct(self.data_len, self.pointer_len, self.message_ref.relative_offset(word_size*i))

    def canonical_pointer(self, new_ref):
        data_len = self.min_member_data_len()
        pointer_len = self.min_member_pointer_len()
        word_len = (data_len + pointer_len) * self.size
        pointer_data = 1 + (7 << 32) + (word_len << 35)
        tag_ref = new_ref.extend_segment(1 + word_len)
        new_ref.set_pointer(pointer_data, tag_ref)
        tag_data = 0 + (self.size << 2) + (data_len << 32) + (pointer_len << 48)
        assert tag_data or self.size == 0
        tag_ref.set_integer(tag_data)
        data_ref = tag_ref.relative_offset(1)
        word_size = data_len + pointer_len
        for i, s in enumerate(self):
            s.canonical_encode(data_ref.relative_offset(word_size*i), data_len, pointer_len)

bit_sizes = [0, 1, 8, 16, 32, 64]

class IntList(object):
    def __init__(self, data_type, size, message_ref):
        self.data_type = data_type
        self.size = size
        self.message_ref = message_ref

    def canonical_pointer(self, new_ref):
        pointer_data = 1 + (self.data_type << 32) + (self.size << 35)
        bit_size = self.size * bit_sizes[self.data_type]
        word_size = bit_size >> 6
        data_ref = new_ref.extend_segment(word_size)
        new_ref.set_pointer(pointer_data, data_ref)
        for i in range(word_size):
            data_ref.relative_offset(i).set_integer(self.message_ref.relative_offset(i).as_integer())
        gubbins_bits = bit_size & 63
        if gubbins_bits:
            gubbins_ref = new_ref.extend_segment(1)
            gubbins_ref.set_integer(((1 << gubbins_bits) - 1) & self.message_ref.relative_offset(word_size).as_integer())

class PointerList(object):
    def __init__(self, size, message_ref):
        self.size = size
        self.message_ref = message_ref

    def canonical_pointer(self, new_ref):
        pointer_data = 1 + (6 << 32) + (self.size << 35)
        data_ref = new_ref.extend_segment(self.size)
        new_ref.set_pointer(pointer_data, data_ref)
        for i in range(self.size):
            self.message_ref.relative_offset(i).follow_pointer().canonical_pointer(data_ref.relative_offset(i))

class Capability(object):
    def __init__(self, index, message_ref):
        self.index = index
        self.message_ref = message_ref

    def canonical_pointer(self, new_ref):
        new_ref.set_integer(3 + (self.index << 32))

if __name__ == '__main__':
    import sys
    zero_always_minus_one = True
    if sys.argv[1:] == ['--zero-always-minus-one=false']:
        zero_always_minus_one = False
    elif sys.argv[1:] == []:
        pass
    else:
        print("Usage: " + sys.argv[0] + " [--zero-always-minus-one=false]")
        print("""
Read non-packed capnp messages from stdin, and output canonical forms.

--zero-always-minus-one    When encoding a zero-size struct pointer,
                           always use offset -1 (default)
""")
        sys.exit(0)
    # Make sure we get a buffer in python 3.
    stdin = getattr(sys.stdin, 'buffer', sys.stdin)
    stdout = getattr(sys.stdout, 'buffer', sys.stdout)
    for segments in read_messages(stdin):
        original = MessageRef(segments, 0, 0, zero_always_minus_one)
        canonical = MessageRef([[0]], 0, 0, zero_always_minus_one)
        original.follow_pointer().canonical_pointer(canonical)
        stdout.write(encode_segments(canonical.segments))
