"""Synthetic in-memory collector vector; prints only an encrypted envelope."""
import hashlib
import json
import pathlib
import sys
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from scripts import preprod_ssh_snapshot as collector

class Session:
    def get_transport(self): return self
    def is_active(self): return True
    def is_authenticated(self): return True
    def get_remote_server_key(self): return self
    def asbytes(self): return b'synthetic-ssh-host-key'

sections = [
    ('objects', 'media_id object_kind media_path path_locator created_at updated_at'),
    ('placements', 'media_id storage_member_id object_id media_path object_kind size_bytes etag state created_at updated_at'),
    ('visibility', 'relative_path hidden updated_at'),
    ('playback', 'media_id media_path preference play_score created_at updated_at'),
    ('lyric_links', 'media_id media_path lyric_id lyric_path created_at updated_at'),
    ('encryption', 'object_kind object_id file_id descriptor_json created_at'),
    ('members', 'member_id relationship_id member_kind transport storage_enabled allocated_bytes used_bytes reserved_bytes physical_free_bytes health writable updated_at'),
    ('relationships', 'relationship_id peer_id peer_endpoint peer_key direction mode state created_at'),
    ('crypto_key_id', 'singleton key_id created_at'),
]
rows = [{'name': name, 'columns': columns.split(), 'rows': []} for name, columns in sections]
rows[0]['rows'] = [['a' * 64, 'audio', 'music/专辑/<歌曲>&.mp3', 'b' * 64, '1', '2']]
rows[-1]['rows'] = [['1', 'c' * 64, '1']]
collector._remote_json = lambda *args, **kwargs: {'node': '1' * 32, 'sections': rows}
receiver = x25519.X25519PrivateKey.from_private_bytes(bytes([8]) * 32)
target = receiver.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
host = hashlib.sha256(b'synthetic-ssh-host-key').hexdigest()
envelope, digest = collector._collect_unlocked(Session(), host, '1' * 32, 'c' * 64,
    '2' * 32, target, '3' * 64, ed25519.Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32),
    {'bytes_per_second': 1048576, 'max_load_ratio': 1, 'max_io_psi': 1}, threading.Event())
print(json.dumps({'envelope': envelope, 'digest': digest, 'host': host}, separators=(',', ':')))
