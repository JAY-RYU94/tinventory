"""ID/PW·JWT·관리자 인가 계약. 세션 회수·권한 하향은 다음 요청부터 적용한다."""
import pytest
from fastapi.testclient import TestClient
from swinventory.server.app import create_app, ApiSettings
from tests.server.test_api import AD, RD, ING
from tests.server.conftest import make_snapshot

PASSWORD = 'test-password-1234'
KEY = 'test-signing-key-' + 'x' * 48

@pytest.fixture
def client(repo, clock):
    return TestClient(create_app(repo, ApiSettings(ingest_tokens=('ing-tok',), read_tokens=('read-tok',), admin_tokens=('adm-tok',)), clock=clock,
        env={'SWINV_JWT_SECRET': KEY}))

def account(client, username='alice', role='read'):
    r = client.post('/v1/users', headers=AD, json={'username': username, 'password': PASSWORD, 'role': role})
    assert r.status_code == 201, r.text
    assert 'password' not in r.text and 'hash' not in r.text
    return r.json()

def login(client, username='alice', password=PASSWORD):
    return client.post('/v1/auth/login', json={'username': username, 'password': password})

def bearer(token): return {'Authorization': 'Bearer ' + token}

def test_password_login_roles_logout_and_existing_agent(client, repo):
    u = account(client)
    r = login(client); assert r.status_code == 200, r.text
    d = r.json(); assert d['token_type'] == 'bearer' and d['access_token'].count('.') == 2
    h = bearer(d['access_token'])
    assert client.get('/v1/whoami', headers=h).json() == {'role': 'read'}
    assert client.get('/v1/users', headers=h).status_code == 403
    assert client.post('/v1/users', headers=h, json={'username': 'evil','password': PASSWORD,'role':'admin'}).status_code == 403
    assert client.get('/v1/hosts', headers=ING).status_code == 403
    assert client.post('/v1/auth/logout', headers=h).status_code == 200
    assert client.get('/v1/hosts', headers=h).status_code == 401
    assert login(client, password='incorrect').status_code == 401
    assert login(client, username='unknown').json() == login(client, password='incorrect').json()
    assert client.get('/v1/users', headers=RD).status_code == 403
    assert client.get('/v1/users').status_code == 401
    assert PASSWORD not in str(repo.list_users())

def test_admin_permissions_disable_and_password_reset_revoke_tokens(client):
    account(client, 'other-admin', 'admin')
    u = account(client)
    old = bearer(login(client).json()['access_token'])
    assert client.patch('/v1/users/'+u['id'], headers=AD, json={'role':'admin'}).status_code == 200
    assert client.get('/v1/hosts', headers=old).status_code == 401
    current = bearer(login(client).json()['access_token'])
    assert client.get('/v1/users', headers=current).status_code == 200
    assert client.patch('/v1/users/'+u['id'], headers=AD, json={'active':False}).status_code == 200
    assert client.get('/v1/hosts', headers=current).status_code == 401
    assert login(client).status_code == 401
    assert client.patch('/v1/users/'+u['id'], headers=AD, json={'active':True,'password':'replacement-pass-123'}).status_code == 200
    assert login(client).status_code == 401
    assert login(client,password='replacement-pass-123').status_code == 200

def test_jwt_expiration_tampering_scope_and_revocation(client, clock):
    u = account(client)
    r = client.post('/v1/tokens', headers=AD,json={'name':'외부 조회','role':'read','user_id':u['id'],'expires_hours':1})
    assert r.status_code == 201, r.text
    d=r.json(); token=d['access_token']; h=bearer(token)
    assert client.get('/v1/hosts',headers=h).status_code == 200
    assert client.get('/v1/users',headers=h).status_code == 403
    assert token not in client.get('/v1/tokens',headers=AD).text
    assert client.get('/v1/hosts',headers=bearer(token[:-8]+'abcdefgh')).status_code == 401
    assert client.delete('/v1/tokens/'+d['id'],headers=AD).status_code == 200
    assert client.get('/v1/hosts',headers=h).status_code == 401
    session=bearer(login(client).json()['access_token'])
    clock.advance(hours=9)
    assert client.get('/v1/hosts',headers=session).status_code == 401
    ingest=client.post('/v1/tokens',headers=AD,json={'name':'수집기','role':'ingest','expires_hours':1}).json()
    assert client.get('/v1/hosts',headers=bearer(ingest['access_token'])).status_code == 403
    assert client.post('/v1/ingest',headers=bearer(ingest['access_token']),json={}).status_code == 422
    assert client.post('/v1/ingest',headers=bearer(ingest['access_token']),json=make_snapshot().to_dict()).status_code == 200

def test_validation_and_login_lockout(client,clock):
    account(client)
    assert client.post('/v1/users',headers=AD,json={'username':'ALICE','password':PASSWORD}).status_code == 409
    assert client.post('/v1/users',headers=AD,json={'username':'bad\u0000id','password':PASSWORD}).status_code == 422
    assert client.post('/v1/users',headers=AD,json={'username':'weak','password':'123'}).status_code == 422
    assert client.post('/v1/tokens',headers=AD,json={'name':'권한 상승','role':'admin','user_id':account(client,'bob')['id']}).status_code == 422
    for _ in range(5): assert login(client,password='incorrect').status_code == 401
    assert login(client).status_code == 429
    clock.advance(minutes=16)
    assert login(client).status_code == 200

def test_bootstrap_is_once_only_and_last_admin_cannot_be_removed(repo,clock):
    env={'SWINV_JWT_SECRET':KEY,'SWINV_ADMIN_USERNAME':'root','SWINV_ADMIN_PASSWORD':PASSWORD}
    c=TestClient(create_app(repo,ApiSettings(),clock=clock,env=env))
    h=bearer(login(c,'root').json()['access_token'])
    root=c.get('/v1/users',headers=h).json()[0]
    assert c.patch('/v1/users/'+root['id'],headers=h,json={'role':'read'}).status_code == 409
    assert c.patch('/v1/users/'+root['id'],headers=h,json={'active':False}).status_code == 409
    create_app(repo,ApiSettings(),clock=clock,env={**env,'SWINV_ADMIN_PASSWORD':'another-password-123'})
    assert login(c,'root').status_code == 200
    changed=c.post('/v1/auth/password',headers=h,json={'current_password':PASSWORD,'new_password':'new-password-1234'})
    assert changed.status_code == 200
    assert c.get('/v1/hosts',headers=h).status_code == 401
    assert login(c,'root',password='new-password-1234').status_code == 200


def test_secrets_are_hashed_and_validation_errors_do_not_reflect_passwords(client,repo):
    import hashlib
    u=account(client)
    assert repo.get_user(u['id'])['password_hash'].startswith('pbkdf2_sha256$600000$')
    assert PASSWORD not in repo.get_user(u['id'])['password_hash']
    d=login(client).json()
    stored=repo.find_token(hashlib.sha256(d['access_token'].encode()).hexdigest())
    assert stored and d['access_token'] not in str(stored)
    assert client.post('/v1/auth/login',json={'username':'bad\u0000id','password':PASSWORD}).status_code==401
    bad=client.post('/v1/users',headers=AD,json={'username':'bad','password':PASSWORD,'role':PASSWORD})
    assert bad.status_code==422 and PASSWORD not in bad.text
    bad=client.post('/v1/auth/login',json={'username':'alice','password':PASSWORD,'unexpected':PASSWORD})
    assert bad.status_code==422 and PASSWORD not in bad.text
    assert client.post('/v1/tokens',headers=RD,json={'name':'bad','role':'ingest'}).status_code==403


@pytest.mark.parametrize('variant',['signature','none','issuer','audience','expiry','future','missing-exp'])
def test_jwt_verification_even_when_token_registry_contains_the_token(client,repo,clock,variant):
    import hashlib,secrets,jwt
    u=account(client)
    tid=secrets.token_hex(16); now=int(clock().timestamp())
    claims=dict(iss='swinventory',aud='swinventory-api',sub=u['id'],jti=tid,iat=now,nbf=now,exp=now+3600,scope='read',kind='api')
    if variant=='issuer': claims['iss']='other'
    if variant=='audience': claims['aud']='other'
    if variant=='expiry': claims['exp']=now-1
    if variant=='future': claims['nbf']=now+3600
    if variant=='missing-exp': del claims['exp']
    key='bad-signature-key-'+'x'*40 if variant=='signature' else KEY
    token=jwt.encode(claims,key if variant!='none' else '',algorithm='HS256' if variant!='none' else 'none')
    with repo.auth_lock():
        repo.add_token(dict(id=tid,token_hash=hashlib.sha256(token.encode()).hexdigest(),user_id=u['id'],generation=1,
            name='독립 검증',role='read',kind='api',created_at=clock().isoformat(),expires_at=now+7200,revoked=False))
    assert client.get('/v1/hosts',headers=bearer(token)).status_code==401


def test_concurrent_last_admin_updates_are_serialized(client,repo,clock):
    from concurrent.futures import ThreadPoolExecutor
    a,b=account(client,'admin-a','admin'),account(client,'admin-b','admin')
    if repo._engine.dialect.name=='postgresql':
        from swinventory.server.repo.sql import SqlInventoryRepository
        # 서로 다른 앱/저장소의 Python 락이 아닌 DB 잠금으로도 보호되는지 확인한다.
        other=TestClient(create_app(SqlInventoryRepository(repo._engine),ApiSettings(admin_tokens=('adm-tok',)),clock=clock,env={'SWINV_JWT_SECRET':KEY}))
    else:
        other=client
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs=[pool.submit(c.patch,'/v1/users/'+u['id'],headers=AD,json={'active':False}) for c,u in [(client,a),(other,b)]]
        statuses=sorted(job.result(timeout=15).status_code for job in jobs)
    assert statuses==[200,409]
    assert sum(u['active'] and u['role']=='admin' for u in client.get('/v1/users',headers=AD).json())==1


def test_unknown_account_rate_limit_cannot_be_bypassed_with_new_ids(client,clock):
    account(client)
    for i in range(30):
        assert login(client,username=f'unknown-{i}').status_code==401
    assert login(client).status_code==429
    clock.advance(minutes=16)
    assert login(client).status_code==200


def test_persistent_signing_key_and_existing_database_upgrade(tmp_path,clock):
    from swinventory.server.repo.sql import SqlInventoryRepository
    env={'SWINV_ADMIN_USERNAME':'root','SWINV_ADMIN_PASSWORD':PASSWORD,'SWINV_SECRET_FILE':str(tmp_path/'secret.key')}
    url=f'sqlite:///{tmp_path}/legacy.db'
    repo=SqlInventoryRepository.from_url(url)
    from tests.server.conftest import make_snapshot
    from swinventory.server.services.ingest import IngestService
    IngestService(repo,clock=clock).ingest(make_snapshot())
    # 구버전 DB 처럼 인증 테이블이 없는 상태에서 시작해 인벤토리를 보존한다.
    from swinventory.server.repo import schema as S
    for table in (S.access_tokens, S.users, S.login_attempts, S.auth_guard):
        table.drop(repo._engine)
    repo=SqlInventoryRepository.from_url(url)
    c=TestClient(create_app(repo,ApiSettings(),clock=clock,env=env))
    token=login(c,'root').json()['access_token']
    assert (tmp_path/'secret.key').stat().st_mode & 0o777==0o600
    again=TestClient(create_app(SqlInventoryRepository.from_url(url),ApiSettings(),clock=clock,env=env))
    assert len(again.get('/v1/hosts',headers=bearer(token)).json())==1
    assert login(again,'root').status_code==200


def test_password_change_wrong_attempts_are_limited(client,clock):
    account(client)
    h=bearer(login(client).json()['access_token'])
    for _ in range(5):
        assert client.post('/v1/auth/password',headers=h,json={'current_password':'wrong','new_password':'replacement-password-123'}).status_code==400
    assert client.post('/v1/auth/password',headers=h,json={'current_password':PASSWORD,'new_password':'replacement-password-123'}).status_code==429
    clock.advance(minutes=16)
    assert client.post('/v1/auth/password',headers=h,json={'current_password':PASSWORD,'new_password':'replacement-password-123'}).status_code==200


def test_environment_bootstrap_and_account_only_restart(tmp_path):
    from swinventory.server.main import create_app_from_env
    env={'SWINV_DB_URL':f'sqlite:///{tmp_path}/accounts.db','SWINV_JWT_SECRET':KEY}
    with pytest.raises(SystemExit): create_app_from_env(env)
    first=TestClient(create_app_from_env({**env,'SWINV_ADMIN_USERNAME':'root','SWINV_ADMIN_PASSWORD':PASSWORD}))
    token=login(first,'root').json()['access_token']
    again=TestClient(create_app_from_env(env))
    assert again.get('/v1/users',headers=bearer(token)).status_code==200
    assert login(again,'root').status_code==200


def test_api_token_becomes_invalid_after_owner_is_disabled(client):
    user=account(client)
    token=client.post('/v1/tokens',headers=AD,json={'name':'소유 계정','role':'read','user_id':user['id']}).json()['access_token']
    assert client.get('/v1/hosts',headers=bearer(token)).status_code==200
    assert client.patch('/v1/users/'+user['id'],headers=AD,json={'active':False}).status_code==200
    assert client.get('/v1/hosts',headers=bearer(token)).status_code==401
    assert client.get('/v1/tokens',headers=AD).json()[0]['status']=='계정 변경으로 무효'
