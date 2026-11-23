"""실제 라우트·인증 의존성을 OpenAPI 문서에 반영한다."""
from fastapi.routing import APIRoute


def configure_openapi(app) -> None:
    groups = {'auth':'계정 인증', 'users':'사용자 관리', 'tokens':'API 토큰',
              'network':'네트워크', 'containers':'컨테이너', 'images':'컨테이너',
              'k8s':'쿠버네티스', 'assets':'자산', 'reports':'리포트',
              'settings':'설정', 'ingest':'수집', 'enrollment':'에이전트 등록',
              'software-products':'업무용 소프트웨어', 'software-request-scopes':'SW 승인 권한 범위',
              'software-requests':'SW 사용 승인 요청', 'vulnerabilities':'취약점·KEV'}
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        part = route.path.split('/')[2] if route.path.startswith('/v1/') else ''
        if not route.tags:
            route.tags = [groups.get(part, '인벤토리')]
        roles = []

        def collect(dependency):
            role = getattr(dependency.call, 'required_role', None)
            if role:
                roles.append(role)
            for nested in dependency.dependencies:
                collect(nested)

        collect(route.dependant)
        if roles:
            priority = {'admin': 3, 'request': 2, 'read': 1, 'ingest': 0}
            role = max(roles, key=lambda value: priority.get(value, 1))
            route.openapi_extra = {**(route.openapi_extra or {}), 'x-required-role':role}
            route.responses.update({401:{'description':'Bearer 토큰이 없거나 만료·회수됨'},
                                    403:{'description':f'{role} 권한 필요'}})
