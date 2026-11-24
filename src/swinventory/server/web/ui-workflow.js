/* Workflow-specific presentation helpers. Data and actions stay in app.js. */
(() => {
  "use strict";

  const namespace = window.SwinventoryUI || (window.SwinventoryUI = {});

  namespace.createWorkflow = function createWorkflow({ h, table, link, compactTime, requestLabel, impactLabel }) {
    const classes = (...items) => items.filter(Boolean).join(" ");
    const plain = (text, className, title) => h("span", { class: className || null, title: title || null }, text || "—");

    function tabs(items, ariaLabel) {
      return h("nav", { class: "view-tabs", "aria-label": ariaLabel }, items.map((item) =>
        h("a", {
          href: item.href, class: item.active ? "active" : null,
          "aria-current": item.active ? "page" : null,
        }, item.label, item.count === undefined ? null : h("span", { class: "view-tab-count" }, String(item.count)))));
    }

    function toolbar(...controls) {
      return h("form", { class: "table-toolbar", role: "search", onsubmit: (event) => event.preventDefault() }, controls);
    }

    function requestState(value) {
      const text = requestLabel(value);
      return plain(text, classes("workflow-state", value && `request-${value}`));
    }

    function impactState(value) {
      const text = impactLabel(value);
      const urgent = value === "confirmed";
      return plain(text, classes("workflow-impact", urgent && "is-confirmed"));
    }

    function approvalTable(rows, { openRequest, serverSort, onServerSort, pageScoped = true } = {}) {
      return table([
        {
          title: "제품", cls: "approval-product", serverSort: "product",
          render: (row) => link(row.product_name || row.name, openRequest(row), "workflow-primary-link"),
        },
        { title: "버전", cls: "approval-version", render: (row) => plain(row.version) },
        { title: "요청 상태", cls: "approval-request-state", serverSort: "status", render: (row) => requestState(row.status) },
        { title: "보안 영향", cls: "approval-security", serverSort: "security", render: (row) => impactState(row.security_impact?.status || row.security_impact) },
        { title: "대상", cls: "approval-targets", align: "right", serverSort: "targets", render: (row) => plain(`${row.host_count}대`, "tabular-nums") },
        { title: "요청자", cls: "approval-requester", serverSort: "requester", render: (row) => plain(row.requester_name) },
        { title: "검토자", cls: "approval-reviewer", serverSort: "assignee", render: (row) => plain(row.assignee_name || "미배정") },
        {
          title: "처리 기한", cls: "approval-due", serverSort: "due",
          sortHint: "전체 요청에서 검토 대기 우선, 처리 기한순으로 정렬합니다.",
          render: (row) => compactTime(row.due_at),
        },
        { title: "요청 번호", cls: "approval-number", serverSort: "request_no", render: (row) => plain(row.request_no, "tabular-nums") },
      ], rows, "승인 요청이 없습니다.", {
        wrapClass: "approval-grid", tableClass: "approval-table",
        ariaLabel: "소프트웨어 사용 승인 요청", caption: "사용 승인 요청 목록",
        serverPage: pageScoped, serverSort, onServerSort, sortScope: "approval-requests",
      });
    }

    function softwareTable(rows, { hostId, role, detailHref, serverPage = false, selection = null, onVisibleRows } = {}) {
      const statusAccess = role === "admin" || role === "request";
      const columns = [
        {
          title: "소프트웨어", cls: "software-name", sort: (row) => row.product_name || row.name,
          render: (row) => detailHref
            ? link(row.product_name || row.name, detailHref(row), "workflow-primary-link")
            : link(row.product_name || row.name, `#/software/${encodeURIComponent(row.name)}`),
        },
        { title: "설치 버전", cls: "software-version", sort: (row) => row.version, render: (row) => plain(row.version || "버전 미기록") },
        { title: "출처", cls: "software-source", render: (row) => plain(row.arch ? `${row.source} · ${row.arch}` : row.source, null, `${row.source || "출처 미기록"}${row.arch ? ` · ${row.arch}` : ""}`) },
        { title: "분류", cls: "software-category", render: (row) => plain(row.category_label || ({
          business_app: "업무용 앱", os_package: "OS 패키지",
          development_dependency: "개발 라이브러리·의존성", needs_review: "분류 확인 필요",
        })[row.category] || row.category || "분류 확인 필요") },
        {
          title: "사용 승인", cls: "software-approval", sort: (row) => row.approval_status,
          render: (row) => plain(({ active: "승인됨", not_active: "미승인", not_required: "대상 제외", classification_required: "분류 확인 필요" })[row.approval_status] || "확인 필요"),
        },
        {
          title: "요청 상태", cls: "software-request-state", sort: (row) => row.request_status,
          render: (row) => {
            if (row.request_status) {
              const href = row.batch_id
                ? `#/sw-requests/batches/${encodeURIComponent(row.batch_id)}`
                : row.request_id ? `#/sw-requests/${encodeURIComponent(row.request_id)}` : null;
              return href ? link(requestLabel(row.request_status), href, "workflow-state-link") : requestState(row.request_status);
            }
            if (!statusAccess) return plain("—", "workflow-state", "요청 이력은 권한 범위에 따라 표시됩니다.");
            return plain("요청 없음", "workflow-state");
          },
        },
        {
          title: "취약점 영향", cls: "software-impact",
          sort: (row) => ({ confirmed: 0, needs_review: 1, not_assessed: 2, no_observed_match: 3, not_affected: 4 })[row.impact_status] ?? 5,
          render: (row) => {
            if (!(row.impact_cve_count > 0)) return impactState(row.impact_status);
            const params = new URLSearchParams();
            if (hostId) params.set("host", hostId);
            params.set("product_source", row.source || "");
            params.set("product_name", row.name || "");
            params.set("product_arch", row.arch || "");
            params.set("product_version", row.version || "");
            const result = link(impactLabel(row.impact_status), `#/cves?${params}`, classes("workflow-impact-link", row.impact_status === "confirmed" && "is-confirmed"));
            result.title = `연결된 CVE ${row.impact_cve_count}건`;
            result.setAttribute("aria-label", `${impactLabel(row.impact_status)}, 연결된 CVE ${row.impact_cve_count}건`);
            return result;
          },
        },
      ];
      if (selection?.enabled) {
        columns.unshift({
          title: "선택", cls: "software-select-column",
          render: (row) => {
            const key = selection.keyOf(row);
            const eligible = selection.canSelect(row);
            const checkbox = h("input", {
              type: "checkbox", class: "batch-selection-checkbox", "data-software-key": key,
              "aria-label": `${row.product_name || row.name} ${row.version || "버전 미기록"} 선택`,
              checked: selection.selectedKeys.has(key), disabled: !eligible,
              onchange: (event) => selection.onToggle(row, event.currentTarget.checked),
            });
            if (!eligible) checkbox.title = selection.disabledReason(row) || "이 설치 항목은 승인 요청 대상이 아닙니다.";
            return h("label", { class: "batch-selection-label" }, checkbox,
              h("span", { class: "sr-only" }, `${row.product_name || row.name} ${row.version || "버전 미기록"} 선택`));
          },
        });
      }
      return table(columns, rows, "설치된 소프트웨어가 없습니다.", {
        wrapClass: "software-grid", tableClass: "software-table",
        ariaLabel: "설치 소프트웨어 및 승인·취약점 상태", caption: "설치 소프트웨어",
        serverPage, sortScope: hostId ? `software-host-${hostId}` : "software-products",
        onVisibleRows,
      });
    }

    function vulnerabilityTable(rows, { detailHref, serverPage = true } = {}) {
      return table([
        { title: "CVE", cls: "vulnerability-id", render: (row) => link(row.cve_id, detailHref(row), "workflow-primary-link") },
        { title: "심각도", cls: "vulnerability-severity", render: (row) => plain(row.cvss_score == null ? "점수 없음" : `${row.cvss_severity || "CVSS"} ${row.cvss_score}`, row.cvss_severity === "CRITICAL" ? "is-urgent" : null) },
        { title: "KEV", cls: "vulnerability-kev", render: (row) => row.vendor ? plain("CISA KEV", "is-urgent") : plain("—") },
        { title: "영향 확인", cls: "vulnerability-confirmed", align: "right", render: (row) => countLink(row, row.confirmed_host_count ?? row.host_count, "confirmed", detailHref) },
        { title: "확인 필요", cls: "vulnerability-review", align: "right", render: (row) => countLink(row, row.needs_review_host_count, "needs_review", detailHref) },
        { title: "영향 없음 판정", cls: "vulnerability-not-affected", align: "right", render: (row) => countLink(row, row.not_affected_host_count, "not_affected", detailHref) },
        { title: "확정 일치 없음", cls: "vulnerability-unmatched", align: "right", render: (row) => countLink(row, row.no_observed_match_host_count, "no_observed_match", detailHref) },
        { title: "NVD 갱신", cls: "vulnerability-sync", render: (row) => compactTime(row.modified_at) },
      ], rows, "CVE가 없습니다.", {
        wrapClass: "vulnerability-grid", tableClass: "vulnerability-table",
        ariaLabel: "CVE 영향 현황", caption: "CVE 영향 현황",
        serverPage, sortScope: "vulnerability-list",
      });
    }

    function countLink(row, count, status, detailHref) {
      if (count == null) return plain("—", "tabular-nums", "이 판정의 집계값을 제공하지 않습니다.");
      const value = `${count}대`;
      return Number(count) > 0
        ? link(value, detailHref(row, status), classes("workflow-impact-link", status === "confirmed" && "is-confirmed"))
        : plain(value, "tabular-nums");
    }

    return { tabs, toolbar, approvalTable, softwareTable, vulnerabilityTable, requestState, impactState };
  };
})();
