"""OpenAPI 인증 계약과 실제 MCP HTTP 전송·조회·회수 경계를 검증한다."""
import json

import pytest
from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from tests.server.conftest import make_snapshot, iface, port, ctr, dpkg
from tests.server.test_api import AD, RD, ING


@pytest.fixture
def client(repo, clock):
    app = create_app(repo, ApiSettings(ingest_tokens=('ing-tok',), read_tokens=('read-tok',), admin_tokens=('adm-tok',)), clock,
                     env={'SWINV_JWT_SECRET': 'integration-test-signing-key-' + 'x'*32})
    with TestClient(app) as c:
        c.post('/v1/ingest', headers=ING, json=make_snapshot(host_id='a', packages=[dpkg('openssl', '3')],
            interfaces=[iface()], ports=[port('tcp', 443)], containers=[ctr()]).to_dict())
        c.post('/v1/ingest', headers=ING, json=make_snapshot(host_id='b', interfaces=[iface()]).to_dict())
        yield c


def rpc(client, method='tools/list', params=None, headers=RD):
    return client.post('/mcp', headers={**headers, 'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25'},
        json={'jsonrpc': '2.0', 'id': 1, 'method': method, **({'params': params} if params is not None else {})})


def call(client, name, args=None, headers=RD):
    response = rpc(client, 'tools/call', {'name': name, 'arguments': args or {}}, headers)
    assert response.status_code == 200, response.text
    return response.json()['result']


def test_openapi_security_and_docs(client):
    schema = client.get('/openapi.json').json()
    assert schema['components']['securitySchemes']['BearerAuth']['scheme'] == 'bearer'
    for path, ops in schema['paths'].items():
        for method, op in ops.items():
            if path.startswith('/v1/') and path != '/v1/auth/login':
                assert op['security'] == [{'BearerAuth': []}], (path, method)
                assert op['x-required-role'] in ('read','request','admin','ingest')
                assert '401' in op['responses'] and '403' in op['responses']
    assert not schema['paths']['/v1/auth/login']['post'].get('security')
    assert schema['paths']['/v1/users']['get']['x-required-role'] == 'admin'
    assert schema['paths']['/v1/ingest']['post']['x-required-role'] == 'ingest'
    assert schema['paths']['/v1/hosts']['get']['x-required-role'] == 'read'
    assert client.get('/docs').status_code == 200
    assert client.get('/redoc').status_code == 200


@pytest.mark.parametrize('headers,status', [({},401), ({'Authorization':'Bearer bad'},401), (ING,403)])
def test_mcp_requires_read_on_every_request(client, headers, status):
    r = rpc(client, headers=headers)
    assert r.status_code == status
    assert r.headers['cache-control'] == 'no-store'
    assert 'read-tok' not in r.text


def test_mcp_initialize_discovery_and_shared_filters(client):
    r = rpc(client, 'initialize', {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'test','version':'1'}})
    assert r.status_code == 200 and r.json()['result']['capabilities']['tools'] is not None
    tools = rpc(client).json()['result']['tools']
    assert {'inventory_overview','inventory_hosts','inventory_software','inventory_ips','inventory_ports','inventory_containers'} <= {t['name'] for t in tools}
    assert all(t['annotations']['readOnlyHint'] for t in tools)
    for name, path, args in [('inventory_hosts','/v1/hosts',{'q':'web'}),
        ('inventory_software','/v1/software-hosts',{'host':'a'}), ('inventory_ips','/v1/network/ips',{'host':'a','conflicts':True}),
        ('inventory_ports','/v1/network/listening',{'host':'a','port':443}), ('inventory_containers','/v1/containers',{'host':'a'})]:
        result = call(client, name, args)
        assert not result.get('isError'), result
        data = result['structuredContent']
        expected = client.get(path, headers=RD, params=args).json()
        assert expected and data['items'] == expected
        assert data['total'] == len(expected)
    page = call(client, 'inventory_hosts', {'page_size':1})['structuredContent']
    assert len(page['items']) == 1 and page['total'] == 2 and page['next_offset'] == 1
    page2 = call(client, 'inventory_hosts', {'page_size':1,'offset':1})['structuredContent']
    assert page2['next_offset'] is None and page2['items'] != page['items']
    assert client.get('/mcp').status_code == 401


@pytest.mark.parametrize('name,args', [('inventory_ports',{'port':0}), ('inventory_hosts',{'page_size':501}),
    ('inventory_hosts',{'url':'https://example.com'}), ('inventory_hosts',{'q':'\x00'}), ('delete_host',{'host':'a'}),
    ('inventory_hosts',{'format':'csv'}), ('inventory_hosts',{'offset':-1})])
def test_mcp_rejects_invalid_or_unlisted_access(client, name, args):
    r = call(client, name, args)
    assert r['isError'] is True
    assert len(client.get('/v1/hosts', headers=RD).json()) == 2


def test_mcp_origin_and_trailing_slash(client):
    assert rpc(client, headers={**RD,'Origin':'https://evil.example'}).status_code == 403
    assert rpc(client, headers={**RD,'Origin':'http://testserver'}).status_code == 200
    assert rpc(client, headers={**RD,'Origin':'http://['}).status_code == 403
    response = client.post('/mcp/', headers={**RD,'Accept':'application/json, text/event-stream'},
                          json={'jsonrpc':'2.0','id':2,'method':'tools/list'})
    assert response.status_code == 200 and response.history == []


def test_mcp_jwt_revocation_and_ingest_role(client):
    from tests.server.test_accounts import account
    user = account(client)
    issue = client.post('/v1/tokens', headers=AD, json={'name':'mcp','role':'read','user_id':user['id'],'expires_hours':1}).json()
    token = issue.get('access_token', issue.get('token'))
    assert token, issue
    hdr = {'Authorization':'Bearer '+token}
    assert rpc(client, headers=hdr).status_code == 200
    assert client.delete('/v1/tokens/'+issue['id'], headers=AD).status_code == 200
    assert rpc(client, headers=hdr).status_code == 401


def test_mcp_masks_internal_failure(client, monkeypatch, repo):
    def broken(*args, **kwargs):
        raise RuntimeError('secret-database-password')
    monkeypatch.setattr(repo, 'list_hosts', broken)
    result = call(client, 'inventory_hosts')
    assert result['isError'] is True
    assert 'secret-database-password' not in json.dumps(result)


def test_official_mcp_client(repo, clock):
    import asyncio
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async def exercise():
        app = create_app(repo, ApiSettings(read_tokens=('read-tok',)), clock, env={})
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), headers=RD) as http:
                async with streamable_http_client('http://testserver/mcp', http_client=http) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        initialized = await session.initialize()
                        assert initialized.serverInfo.name == 'swinventory'
                        tools = await session.list_tools()
                        assert len(tools.tools) == 13
                        for tool in tools.tools:
                            result = await session.call_tool(tool.name, {})
                            assert not result.isError, (tool.name, result)
                            assert result.structuredContent is not None
    asyncio.run(exercise())


def test_mcp_jwt_account_change_and_expiry(client, clock):
    from tests.server.test_accounts import account, login, bearer
    account(client, 'root-admin', 'admin')
    user = account(client)
    token = bearer(login(client).json()['access_token'])
    assert rpc(client, headers=token).status_code == 200
    assert client.patch('/v1/users/'+user['id'], headers=AD, json={'active':False}).status_code == 200
    assert rpc(client, headers=token).status_code == 401
    assert client.patch('/v1/users/'+user['id'], headers=AD, json={'active':True}).status_code == 200
    token = bearer(login(client).json()['access_token'])
    clock.advance(hours=9)
    assert rpc(client, headers=token).status_code == 401


def test_mcp_output_limit_and_page_before_limit(client, monkeypatch, repo):
    from copy import deepcopy
    original = repo.list_hosts()[0]
    rows = [{**deepcopy(original), 'host_id':str(i), 'hostname':'x'*10000} for i in range(250)]
    monkeypatch.setattr(repo, 'list_hosts', lambda *args, **kwargs: rows)
    page = call(client, 'inventory_hosts', {'page_size':1})
    assert not page.get('isError') and len(page['structuredContent']['items']) == 1
    assert call(client, 'inventory_hosts', {'page_size':500})['isError'] is True
