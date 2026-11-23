/* Shared table renderer for the no-build browser application. */
(() => {
  "use strict";

  const namespace = window.SwinventoryUI || (window.SwinventoryUI = {});

  namespace.createTable = function createTable({ h, pageRows = 200, empty }) {
    const collator = new Intl.Collator("ko", { numeric: true, sensitivity: "base" });
    const blank = (value) => value === null || value === undefined || value === "" || (typeof value === "number" && Number.isNaN(value));
    const compare = (left, right) => (typeof left === "number" && typeof right === "number"
      ? left - right
      : collator.compare(String(left), String(right)));
    const memory = new Map();

    function orderedRows(rows, column, direction) {
      const keyed = rows.map((row, index) => ({ row, index, key: column.sort(row) }));
      const present = keyed.filter((item) => !blank(item.key))
        .sort((left, right) => direction * compare(left.key, right.key) || left.index - right.index);
      return [...present, ...keyed.filter((item) => blank(item.key))].map((item) => item.row);
    }

    function table(columns, rows, emptyMessage, options = {}) {
      if (!rows.length) return empty ? empty(emptyMessage || "데이터가 없습니다.") : h("div", { class: "empty" }, emptyMessage || "데이터가 없습니다.");
      const signature = `${options.sortScope || ""}|${columns.map((column) => `${column.title}:${column.serverSort || (column.sort ? "local" : "-")}`).join("|")}`;
      const remembered = memory.get(signature) || { col: -1, dir: 1 };
      memory.set(signature, remembered);
      let visible = pageRows;
      const classes = (...items) => items.filter(Boolean).join(" ");
      const box = h("div", {
        class: classes("scroll", rows.length > 10 && "tall", options.scrollClass),
        tabindex: "0", role: "region", "aria-label": options.ariaLabel || "표 데이터",
      });
      const moreBtn = h("button", { type: "button", onclick: () => { visible += pageRows; draw(); if (moreBtn.hidden) box.focus(); } });
      const info = h("span", { class: "muted", role: "status" });
      const more = h("div", { class: "more" }, moreBtn, info);

      const toggle = (index) => {
        const column = columns[index];
        if (column.serverSort && options.onServerSort) {
          const state = options.serverSort || {};
          const first = column.desc ? "desc" : "asc";
          const direction = state.key === column.serverSort && state.direction === first
            ? (first === "asc" ? "desc" : "asc")
            : first;
          options.onServerSort(column.serverSort, direction);
          return;
        }
        const first = column.desc ? -1 : 1;
        if (remembered.col !== index) { remembered.col = index; remembered.dir = first; }
        else if (remembered.dir === first) remembered.dir = -first;
        else { remembered.col = -1; remembered.dir = 1; }
        draw(index);
      };

      function draw(refocus) {
        const serverKey = options.serverSort?.key || "";
        const serverDirection = options.serverSort?.direction || "asc";
        const localSorted = remembered.col >= 0;
        const serverSorted = !!options.serverSort?.key;
        const ordered = localSorted ? orderedRows(rows, columns[remembered.col], remembered.dir) : rows;
        const shown = ordered.slice(0, visible);
        const header = h("tr", null, columns.map((column, index) => {
          const serverActive = !!column.serverSort && serverKey === column.serverSort;
          const localActive = !column.serverSort && remembered.col === index;
          const active = serverActive || localActive;
          const direction = serverActive ? serverDirection : remembered.dir === 1 ? "asc" : "desc";
          const sortValue = active ? (direction === "asc" ? "ascending" : "descending") : null;
          const cellClass = classes(column.headerClass, column.cls, column.align === "right" && "numeric");
          if (!column.sort && !column.serverSort) return h("th", { scope: "col", class: cellClass || null }, column.title || h("span", { class: "sr-only" }, column.srTitle || "표시"));
          return h("th", { scope: "col", class: cellClass || null, "aria-sort": sortValue },
            h("button", {
              type: "button", class: "sort", "data-col": String(index),
              "aria-label": `${column.title} 정렬${active ? (direction === "asc" ? " 오름차순" : " 내림차순") : ""}`,
              title: column.sortHint || undefined,
              onclick: () => toggle(index),
            }, column.title, h("span", { class: "arrow", "aria-hidden": "true" }, active ? (direction === "asc" ? "▲" : "▼") : "")));
        }));
        const body = shown.map((row) => h("tr", { class: options.rowClass ? options.rowClass(row) : null }, columns.map((column) => {
          const cellClass = classes(column.mono && "mono", column.nowrap && "nowrap", column.align === "right" && "numeric", column.cls);
          return h("td", { class: cellClass || null }, column.render(row));
        })));
        const tableElement = h("table", { class: classes("data-grid", options.tableClass) },
          h("caption", { class: "sr-only" }, options.caption || options.ariaLabel || "표 데이터"),
          h("thead", null, header), h("tbody", null, body));
        tableElement.style.setProperty("--cols", String(columns.length));
        while (box.firstChild) box.removeChild(box.firstChild);
        box.append(tableElement);
        const remaining = ordered.length - shown.length;
        more.hidden = rows.length <= pageRows && !(options.serverPage && (localSorted || serverSorted));
        moreBtn.hidden = remaining <= 0;
        moreBtn.textContent = `${Math.min(pageRows, remaining)}개 더 보기`;
        info.textContent = options.serverPage
          ? `현재 페이지 ${shown.length}건 표시${serverSorted ? " · 전체 결과 기준 정렬" : localSorted ? " · 현재 페이지 안에서 정렬" : ""}`
          : `전체 ${ordered.length}개 중 ${shown.length}개 표시`;
        if (refocus !== undefined) {
          const button = box.querySelector(`th button.sort[data-col="${refocus}"]`);
          if (button) button.focus();
        }
      }
      draw();
      return h("div", { class: classes("table-wrap", options.wrapClass) }, box, more);
    }

    return { table, clearSortMemory: () => memory.clear() };
  };
})();
