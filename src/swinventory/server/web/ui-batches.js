/* 호스트별 승인 요청 표 표현. 권한·데이터 검증·요청은 app.js가 담당한다. */
(() => {
  "use strict";

  const namespace = window.SwinventoryUI || (window.SwinventoryUI = {});

  namespace.createBatches = function createBatches({ h, table, link, compactTime, requestLabel, impactLabel }) {
    const plain = (value, className, title) => h("span", {
      class: className || null, title: title || null,
    }, value === null || value === undefined || value === "" ? "—" : String(value));
    const num = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
    const counts = (batch) => batch.status_counts || {};
    const impactCounts = (batch) => batch.security_impact_counts || {};

    function statusSummary(batch) {
      const c = counts(batch);
      const total = num(batch.item_count);
      const approved = num(c.approved), rejected = num(c.rejected), withdrawn = num(c.withdrawn);
      const needsChanges = num(c.needs_changes);
      const pending = num(c.submitted) + num(c.reviewing);
      const terminal = num(batch.terminal_count);
      if (total > 0 && terminal === total) {
        return `처리 완료 · 승인 ${approved} / 반려 ${rejected} / 철회 ${withdrawn}`;
      }
      const handled = approved + rejected + withdrawn;
      if (handled > 0) return `일부 처리 · 승인 ${approved} / 반려 ${rejected} · 남은 요청 ${pending + needsChanges}건`;
      if (needsChanges > 0) return `요청자 보완 대기 ${needsChanges}건`;
      if (pending > 0) return `검토 중 ${pending}건`;
      return batch.status === "mixed" ? "요청별 처리 상태 확인" : requestLabel(batch.status);
    }

    function securitySummary(batch) {
      const c = impactCounts(batch);
      const parts = [];
      if (num(c.confirmed)) parts.push(`영향 확인 ${num(c.confirmed)}`);
      if (num(c.needs_review)) parts.push(`확인 필요 ${num(c.needs_review)}`);
      if (num(c.not_assessed)) parts.push(`미평가 ${num(c.not_assessed)}`);
      if (num(c.no_observed_match)) parts.push(`확정 일치 없음 ${num(c.no_observed_match)}`);
      if (num(c.not_affected)) parts.push(`영향 없음 ${num(c.not_affected)}`);
      return parts.length ? parts.join(" · ") : "정보 없음";
    }

    function queueTable(rows, { href, serverSort, onServerSort } = {}) {
      const batchLink = (row, label) => {
        const anchor = link(label, href(row), "batch-queue-link");
        anchor.dataset.batchId = String(row.id);
        return anchor;
      };
      return table([
        { title: "호스트 / 자산", cls: "batch-queue-host", serverSort: "host",
          render: (row) => h("span", null,
            batchLink(row, row.host?.hostname || row.host_id),
            h("span", { class: "batch-queue-sub" }, row.host?.asset_no || "자산 미등록")) },
        { title: "소프트웨어 수", cls: "batch-queue-items", align: "right", sort: (row) => row.item_count,
          render: (row) => plain(`${num(row.item_count)}개`, "tabular-nums") },
        { title: "진행 / 결과", cls: "batch-queue-status", serverSort: "status", render: (row) => plain(statusSummary(row), "batch-status") },
        { title: "보안 영향", cls: "batch-queue-security", render: (row) => plain(securitySummary(row), "batch-impact") },
        { title: "요청자", cls: "batch-queue-requester", render: (row) => plain(row.requester_name) },
        { title: "검토자", cls: "batch-queue-reviewer", render: (row) => plain((row.assignees || []).join(", ") || "미배정") },
        { title: "처리 기한", cls: "batch-queue-due", serverSort: "due", render: (row) => compactTime(row.due_at) },
        { title: "요청 번호", cls: "batch-queue-number", serverSort: "batch_no",
          render: (row) => batchLink(row, row.batch_no) },
      ], rows, "승인 요청이 없습니다.", {
        wrapClass: "batch-queue-grid", tableClass: "batch-queue-table",
        ariaLabel: "호스트별 승인 요청", caption: "호스트별 승인 요청",
        serverPage: true, serverSort, onServerSort, sortScope: "software-request-batches",
      });
    }

    function itemTable(rows, { actionsFor, detailHref, childHref, cveHref, selection = null, commonPurpose } = {}) {
      const columns = [
        { title: "제품", cls: "batch-item-product", render: (row) => h("span", null,
          detailHref ? link(row.product_name || row.name, detailHref(row), "workflow-primary-link") : plain(row.product_name || row.name),
          h("span", { class: "batch-item-sub" }, `${row.source || "출처 미기록"}${row.arch ? ` · ${row.arch}` : ""}`),
          childHref ? h("span", { class: "batch-item-sub" }, link(row.request_no || `요청 ${row.id}`, childHref(row), "batch-child-link")) : null,
          row.purpose !== undefined && row.purpose !== commonPurpose
            ? h("details", { class: "batch-item-current-request" }, h("summary", null, "보완 후 요청 내용"),
              h("p", null, h("strong", null, "수정된 요청 사유"), h("br"), row.purpose || "기록 없음")) : null) },
        { title: "버전", cls: "batch-item-version", render: (row) => plain(row.version) },
        { title: "설치 상태", cls: "batch-item-installed", render: (row) => row.current_installed === true
          ? plain("현재 설치됨") : plain("현재 설치되지 않음", "batch-installation-missing") },
        { title: "요청 상태", cls: "batch-item-status", render: (row) => h("span", null,
          plain(requestLabel(row.status), "batch-status"),
          row.decision_reason && ["needs_changes", "rejected"].includes(row.status)
            ? h("details", { class: "batch-item-decision" }, h("summary", null, "처리 사유"), h("p", null, row.decision_reason)) : null) },
        { title: "현재 승인", cls: "batch-item-approval", render: (row) => plain(
          row.approval_status === "active" ? `승인됨${row.current_approval_until ? ` · ${compactTime(row.current_approval_until).textContent}` : ""}`
            : row.approval_status === "not_active" ? "미승인" : "확인 필요") },
        { title: "보안 영향", cls: "batch-item-impact", render: (row) => {
          const status = row.security_impact?.status || row.security_impact;
          return plain(impactLabel(status), `batch-impact${status === "confirmed" ? " is-confirmed" : ""}`);
        } },
        { title: "CVE", cls: "batch-item-cves", render: (row) => (row.impact_cves || []).length
          ? h("span", { class: "batch-cve-list" }, row.impact_cves.map((cve) => h("span", { class: "batch-cve-item" },
            cve.is_kev ? h("span", { class: "batch-kev" }, "KEV") : null,
            link(cve.cve_id, cveHref ? cveHref(row, cve) : `#/cves/${encodeURIComponent(cve.cve_id)}`),
            h("span", { class: "batch-cve-impact" }, ` · ${impactLabel(cve.impact_status)}`))))
          : plain("매핑 없음") },
        { title: "담당 / 기한", cls: "batch-item-assignment", render: (row) => h("span", null,
          plain(row.assignee_name || "미배정"), h("span", { class: "batch-item-sub" }, compactTime(row.due_at))) },
        { title: "작업", cls: "batch-item-actions", render: (row) => h("div", { class: "batch-item-action-list" }, actionsFor(row)) },
      ];
      if (selection) columns.unshift({ title: "선택", cls: "batch-item-select", render: (row) => {
        const key = String(row.id);
        const eligible = selection.canSelect(row);
        const checkbox = h("input", {
          type: "checkbox", class: "batch-item-selection", "data-request-id": key,
          checked: selection.selected.has(key), disabled: !eligible,
          "aria-label": `${row.product_name || row.name} ${row.version || "버전 미기록"} 요청 선택`,
          onchange: (event) => selection.onToggle(row, event.currentTarget.checked),
        });
        if (!eligible) checkbox.title = selection.disabledReason(row) || "현재 처리할 수 없는 항목입니다.";
        return checkbox;
      }});
      return table(columns, rows, "요청 항목이 없습니다.", {
        wrapClass: "batch-item-grid", tableClass: "batch-item-table",
        ariaLabel: "소프트웨어 승인 요청 항목", caption: "소프트웨어별 요청 상태",
      });
    }

    return { queueTable, itemTable, statusSummary, securitySummary };
  };
})();
