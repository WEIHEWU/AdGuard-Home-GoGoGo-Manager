import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// 轻量级标准 PKZIP / DEFLATE (RFC-1951/ZIP) 内存打包器（仅依赖 dart:io ZLibCodec）
class DiagnosticZipBuilder {
  static final List<int> _crcTable = _buildCrcTable();

  static List<int> _buildCrcTable() {
    final table = List<int>.filled(256, 0);
    for (var i = 0; i < 256; i++) {
      var c = i;
      for (var k = 0; k < 8; k++) {
        c = (c & 1) != 0 ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[i] = c;
    }
    return table;
  }

  static int _crc32(List<int> data) {
    var crc = 0xFFFFFFFF;
    for (final b in data) {
      crc = _crcTable[(crc ^ b) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF;
  }

  static Uint8List buildZip(Map<String, String> textEntries) {
    final out = BytesBuilder(copy: false);
    final centralDir = BytesBuilder(copy: false);
    final codec = ZLibCodec(raw: true, level: 6);
    var entryCount = 0;

    final now = DateTime.now().toUtc();
    final dosTime = ((now.hour & 0x1F) << 11) |
        ((now.minute & 0x3F) << 5) |
        ((now.second ~/ 2) & 0x1F);
    final dosDate = (((now.year - 1980).clamp(0, 127) & 0x7F) << 9) |
        ((now.month & 0x0F) << 5) |
        (now.day & 0x1F);

    for (final entry in textEntries.entries) {
      final nameBytes = utf8.encode(entry.key);
      final rawBytes = utf8.encode(entry.value);
      final deflated = codec.encode(rawBytes);

      final useDeflate = deflated.length < rawBytes.length;
      final method = useDeflate ? 8 : 0;
      final payload = useDeflate ? deflated : rawBytes;
      final crc = _crc32(rawBytes);
      final localOffset = out.length;

      // Local File Header (30 bytes + filename)
      _writeUint32(out, 0x04034B50);
      _writeUint16(out, 20); // version needed
      _writeUint16(out, 0x0800); // UTF-8 filename flag
      _writeUint16(out, method);
      _writeUint16(out, dosTime);
      _writeUint16(out, dosDate);
      _writeUint32(out, crc);
      _writeUint32(out, payload.length);
      _writeUint32(out, rawBytes.length);
      _writeUint16(out, nameBytes.length);
      _writeUint16(out, 0);
      out.add(nameBytes);
      out.add(payload);

      // Central Directory Header (46 bytes + filename)
      _writeUint32(centralDir, 0x02014B50);
      _writeUint16(centralDir, 20);
      _writeUint16(centralDir, 20);
      _writeUint16(centralDir, 0x0800);
      _writeUint16(centralDir, method);
      _writeUint16(centralDir, dosTime);
      _writeUint16(centralDir, dosDate);
      _writeUint32(centralDir, crc);
      _writeUint32(centralDir, payload.length);
      _writeUint32(centralDir, rawBytes.length);
      _writeUint16(centralDir, nameBytes.length);
      _writeUint16(centralDir, 0);
      _writeUint16(centralDir, 0);
      _writeUint16(centralDir, 0);
      _writeUint16(centralDir, 0);
      _writeUint32(centralDir, 0);
      _writeUint32(centralDir, localOffset);
      centralDir.add(nameBytes);

      entryCount++;
    }

    final cdOffset = out.length;
    final cdBytes = centralDir.takeBytes();
    out.add(cdBytes);

    // End of Central Directory (22 bytes)
    _writeUint32(out, 0x06054B50);
    _writeUint16(out, 0);
    _writeUint16(out, 0);
    _writeUint16(out, entryCount);
    _writeUint16(out, entryCount);
    _writeUint32(out, cdBytes.length);
    _writeUint32(out, cdOffset);
    _writeUint16(out, 0);

    return out.takeBytes();
  }

  static void _writeUint16(BytesBuilder b, int val) {
    b.addByte(val & 0xFF);
    b.addByte((val >> 8) & 0xFF);
  }

  static void _writeUint32(BytesBuilder b, int val) {
    b.addByte(val & 0xFF);
    b.addByte((val >> 8) & 0xFF);
    b.addByte((val >> 16) & 0xFF);
    b.addByte((val >> 24) & 0xFF);
  }
}
