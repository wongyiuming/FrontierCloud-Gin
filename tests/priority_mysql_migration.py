"""Exercise actual generation-3 MySQL DDL and interrupted generation-4 upgrade."""
import argparse
import json
import os
import pathlib
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--container', required=True)
parser.add_argument('--binary', required=True)
parser.add_argument('--secrets', type=pathlib.Path, required=True)
parser.add_argument('--port', type=int, required=True)
args = parser.parse_args()
assert args.container.startswith('fc-admin-priority-mysql-')
assert str(args.secrets).startswith('/tmp/fc-admin-priority-mysql-')
root = pathlib.Path(__file__).resolve().parents[1]


def sql(statement, success=True):
    result = subprocess.run(['docker', 'exec', '-i', args.container, 'sh', '-c',
        'MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_password) mysql -h 127.0.0.1 --batch --skip-column-names -u media_admin fc_priority'],
        input=statement, text=True, capture_output=True)
    assert (result.returncode == 0) == success, result.stderr
    return result.stdout.strip()


document = json.loads((root / 'migrations/mysql/0003-schema.json').read_text())
sql(';\n'.join(document['statements']) + ';')
sql("INSERT INTO frontiercloud_schema VALUES(1,3,123); INSERT INTO ip_security_projection(singleton) VALUES(1); "
    "INSERT INTO media_playback_stats VALUES('directory','music/old',7,500,'2026-01-01','2026-01-02'),"
    "('media','music/old/a.mp3',8,100,'2026-02-01','2026-02-02'); "
    "CREATE INDEX keep_priority_index ON media_playback_stats(play_score);")
facts_query = 'SELECT media_id,media_path,play_score,preference,created_at,updated_at FROM media_playback_stats ORDER BY media_id'
original = sql(facts_query)
sql("UPDATE media_playback_stats SET preference=500000 WHERE media_id='media'", success=False)
env = {key: value for key, value in os.environ.items() if key in {'PATH', 'LANG'}}
env.update(DB_TYPE='mysql', MYSQL_HOST='127.0.0.1', MYSQL_PORT=str(args.port), MYSQL_DATABASE='fc_priority',
           MYSQL_USER='media_admin', MYSQL_PASSWORD_FILE=str(args.secrets / 'mysql_password'),
           DATA_ROOT=str(args.secrets.parent / 'data'), SECRETS_DIR=str(args.secrets), TLS_ENABLED='false', SERVER_NAME='localhost')
for attempt in range(3):
    if attempt == 1:
        # Atomic ALTER committed, but journal/marker update never ran.
        sql('UPDATE frontiercloud_schema SET generation=3; DELETE FROM frontiercloud_schema_migrations WHERE generation=4')
    subprocess.run([args.binary, 'migrate'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    assert sql(facts_query) == original
    assert sql('SELECT generation FROM frontiercloud_schema') == '5'
    assert sql("SELECT data_type FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='media_playback_stats' AND column_name='preference'") == 'int'
    assert sql("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='media_playback_stats' AND index_name='keep_priority_index'") == '1'
sql("UPDATE media_playback_stats SET preference=500000 WHERE media_id='media'")
sql("UPDATE media_playback_stats SET preference=500001 WHERE media_id='media'", success=False)
sql("UPDATE media_playback_stats SET preference=-8 WHERE media_id='media'", success=False)
sql("DELETE FROM media_playback_stats WHERE media_id IN ('directory','media'); DROP INDEX keep_priority_index ON media_playback_stats")
print('PASS: actual MySQL 3->4 preserves facts/indexes, interrupted-DDL recovery, bounds')
