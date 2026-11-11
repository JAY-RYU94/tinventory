#!/bin/bash
# C# 에이전트 결함 주입(변이) 검증. 컨테이너 안에서 저장소 복사본(/work)에 변이를 하나씩 적용하고 테스트가 실패하는지 본다.
# 호스트 파일은 건드리지 않는다. 모든 줄이 "Failed!" 여야 하고, "Passed!" 가 나오면 그 변이를 잡는 테스트가 없다는 뜻이다.
#   windows-agent/mutation.sh
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD:/repo:ro" -v swinv-nuget:/root/.nuget/packages -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 \
  mcr.microsoft.com/dotnet/sdk:10.0 bash -c '
set -u
rm -rf /work && mkdir -p /work && cp -r /repo/windows-agent /work/ && mkdir -p /work/contracts && cp -r /repo/contracts/golden /work/contracts/ && cp /repo/contracts/hardware-vectors.json /work/contracts/
cd /work/windows-agent
dotnet build tests/Swinventory.Agent.Tests -v q --nologo >/dev/null 2>&1 || { echo "기준선 빌드 실패"; exit 1; }
mutate() { # label file pattern replacement  (컴파일 경고가 오류로 처리되므로 "도달 불가 코드"가 생기지 않는 형태로 쓴다)
  local label=$1 file=$2 pat=$3 rep=$4
  cp "$file" /tmp/orig.cs
  PAT="$pat" REP="$rep" perl -0pi -e "s/\Q\$ENV{PAT}\E/\$ENV{REP}/" "$file"
  if cmp -s "$file" /tmp/orig.cs; then printf "%-60s NOCHANGE(패턴 없음 — 스크립트를 갱신한다)\n" "$label"; return; fi
  out=$(dotnet test tests/Swinventory.Agent.Tests -v q --nologo 2>&1 | grep -E "error CS|Passed!|Failed!" | tail -1)
  printf "%-60s %s\n" "$label" "$out"
  cp /tmp/orig.cs "$file"
}
mutate_re() { # label file regex replacement — 따옴표가 섞인 코드는 정규식으로 맞춘다
  local label=$1 file=$2 pat=$3 rep=$4
  cp "$file" /tmp/orig.cs
  PAT="$pat" REP="$rep" perl -0pi -e "s/\$ENV{PAT}/\$ENV{REP}/" "$file"
  if cmp -s "$file" /tmp/orig.cs; then printf "%-60s NOCHANGE(패턴 없음 — 스크립트를 갱신한다)\n" "$label"; return; fi
  out=$(dotnet test tests/Swinventory.Agent.Tests -v q --nologo 2>&1 | grep -E "error CS|Passed!|Failed!" | tail -1)
  printf "%-60s %s\n" "$label" "$out"
  cp /tmp/orig.cs "$file"
}
S=src/Swinventory.Agent
T=$S/Transport/Transport.cs; C=$S/Collectors/Collectors.cs
mutate "리다이렉트 추종(토큰 유출)" $T "AllowAutoRedirect = false" "AllowAutoRedirect = true"
mutate "사설 CA 에서 호스트명 검증 해제" $T "if ((errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;" ""
mutate "인증서 검증 전부 통과" $T "if (errors == SslPolicyErrors.None) return true;" "if (errors == SslPolicyErrors.None || errors != SslPolicyErrors.None) return true;"
mutate "mTLS 클라이언트 인증서 미전송" $T "ClientCertificates = _clientCertificate is null ? null : new X509CertificateCollection { _clientCertificate }," ""
mutate "401 을 영구 거절로 분류" $T "new() { 400, 413, 422 }" "new() { 400, 401, 413, 422 }"
mutate "토큰 마스킹 제거" $T "token.Length > 0 ? text.Replace(token, \"***\", StringComparison.Ordinal) : text" "text"
mutate "스풀 비우기 결과 무시(순서 깨짐)" $T "if (!Flush())" "if (!Flush() && DateTime.UtcNow.Year < 2000)"
mutate "스풀 상한 미적용" $T "foreach (var old in Files().Take(Math.Max(0, Files().Count() - _max))) File.Delete(old);" ""
mutate "스풀 디렉터리 권한 미설정" $T "else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);" "else Directory.CreateDirectory(path);"
mutate "스풀을 최신순으로 꺼냄" $T ".OrderBy(f => Path.GetFileName(f), StringComparer.Ordinal)" ".OrderByDescending(f => Path.GetFileName(f), StringComparer.Ordinal)"
mutate "업데이트 항목 필터 제거" $C "if (UpdateTypes.Contains(Values.Str(vals, \"ReleaseType\")) || KbKey.IsMatch(sub)) continue;" ""
mutate "SystemComponent 필터 제거" $C "if (Values.Num(vals, \"SystemComponent\") == 1 || Values.Str(vals, \"ParentKeyName\").Length > 0) continue;" ""
mutate "UDP 임시 포트 미제외" $C "raw.Udp.Where(e => e.Port < ephemeralStart)" "raw.Udp.Where(e => e.Port < ephemeralStart || e.Port >= 0)"
mutate "루프백 유형 인터페이스 미제외" $C "if (pi.InterfaceType == \"Loopback\") continue;" ""
mutate "링크 로컬 주소 미제외" $C "!IPAddress.IsLoopback(a.Ip) && !NetUtil.IsLinkLocal(a.Ip)" "!IPAddress.IsLoopback(a.Ip)"
mutate "식별 정보 없는 장치 미제외" $C "if (mac.Length == 0 && addresses.Count == 0) continue;" ""
mutate "IPv4 매핑 주소 미정규화" $C "return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;" "return address;"
mutate "재부팅 필요 키 하나 무시" $C "registry.KeyExists(WindowsKeys.RebootPending) || registry.KeyExists(WindowsKeys.RebootRequired)" "registry.KeyExists(WindowsKeys.RebootPending)"
mutate "핫픽스 단일 객체 처리 제거" $C "doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToList() : new List<JsonElement> { doc.RootElement }" "doc.RootElement.EnumerateArray().ToList()"
mutate "수집 시각을 UTC 로 바꾸지 않음" $S/Orchestrator.cs "clock().ToUniversalTime().ToString" "clock().ToString"
mutate "https 강제 해제" $S/Config.cs "if (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && AllowInsecureHttp))" "if (false)"
mutate "비 Windows 에서도 수집 시도" $S/Cli.cs "if (!rt.IsWindows)" "if (!rt.IsWindows && rt.Sleep is null)"
mutate_re "토큰 파일의 BOM·CRLF 미제거" $S/Config.cs "File\\.ReadAllText\\(cfg\\.TokenFile\\)\\.Trim\\(\\)\\.TrimStart\\([^)]*\\)\\.Trim\\(\\)" "File.ReadAllText(cfg.TokenFile)"
mutate "JSON 키를 PascalCase 로(계약 위반)" $S/Models/Models.cs "PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower," ""
mutate "프로세스 인자를 한 문자열로 합침(셸 해석)" $S/Runtime/Runtime.cs "foreach (var a in args.Skip(1)) psi.ArgumentList.Add(a);" "psi.Arguments = string.Join(\" \", args.Skip(1));"
mutate "doctor: 401 을 정상으로 판정" $S/Doctor.cs "401 => (\"FAIL\"," "401 => (\"PASS\","
mutate "doctor: 토큰 마스킹 제거" $S/Doctor.cs "ex.Message.Replace(t, \"***\", StringComparison.Ordinal)" "ex.Message"
H=$S/Collectors/Hardware.cs
mutate "장비: 워크그룹명을 도메인으로" $H "var domain = joined ? Str(sys, \"Domain\").ToLowerInvariant() : \"\";" "var domain = Str(sys, \"Domain\").ToLowerInvariant();"
mutate "장비: 컨테이너 판정 제거" $H "if (!string.IsNullOrEmpty(container) && container != \"none\") return (\"container\", container);" ""
mutate "장비: 시리얼 자리표시자 허용" $H "\"to be filled by o.e.m.\", " ""
mutate_re "장비: 선행 점 FQDN 에서 도메인을 만들어 냄" $H "TrimEnd\\([^)]*\\)" "Trim((char)46)"
mutate "장비: 근거가 없어도 물리로 단정" $H "return haystack.Length > 0 ? (\"physical\", \"\") : (\"unknown\", \"\");" "return (\"physical\", \"\");"
mutate "장비: 제어문자 미제거" $H "Control().Replace(value ?? \"\", \"\").Trim()" "(value ?? \"\").Trim()"
mutate "장비: BIOS 명령이 없을 때 수집 전체 실패" $H "when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)" "when (ex is System.ComponentModel.Win32Exception)"
mutate "장비: 수집 결과를 빌더에 반영하지 않음" $H "protected override void Contribute(SnapshotBuilder b, HardwareInfo value) => b.Hardware = value;" "protected override void Contribute(SnapshotBuilder b, HardwareInfo value) { }"
mutate "장비: 프로필에서 수집기 제외" $S/Orchestrator.cs ", new WinHardware(runner)," ","
mutate "장비: 오케스트레이터가 스냅샷에 옮기지 않음" $S/Orchestrator.cs "snapshot.Hardware = builder.Hardware;" ""
mutate "장비: 시스템 조회 실패를 성공으로" $H "if (sys.ExitCode != 0) throw new InvalidOperationException" "if (sys.ExitCode != 0 && sys.ExitCode < 0) throw new InvalidOperationException"
mutate "장비: vmware 판정 패턴 제거" $H "(Rx(\"vmware\"), \"vmware\")," ""
echo "[완료]"
'
