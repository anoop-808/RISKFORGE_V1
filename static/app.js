document.addEventListener("DOMContentLoaded", () => {
    const body = document.body;
    const sidebar = document.getElementById("sidebar");
    const collapse = document.getElementById("sidebar-toggle");
    const mobileToggle = document.getElementById("mobile-nav-toggle");
    if (collapse) collapse.addEventListener("click", () => {
        body.classList.toggle("sidebar-collapsed");
        const expanded = !body.classList.contains("sidebar-collapsed");
        collapse.setAttribute("aria-expanded", String(expanded));
        collapse.setAttribute("aria-label", expanded ? "Collapse navigation" : "Expand navigation");
        collapse.title = expanded ? "Collapse navigation" : "Expand navigation";
    });
    if (mobileToggle && sidebar) mobileToggle.addEventListener("click", () => {
        const open = sidebar.classList.toggle("is-open");
        mobileToggle.setAttribute("aria-expanded", String(open));
    });

    const form = document.getElementById("scan-form");
    if (form) form.addEventListener("submit", () => {
        const button = form.querySelector("button[type='submit']");
        if (!button) return;
        button.disabled = true;
        button.classList.add("is-loading");
        button.setAttribute("aria-busy", "true");
        const statusLabel = document.querySelector("#engine-status .status-label");
        if (statusLabel) statusLabel.textContent = "Scanning…";
    });

    const status = document.getElementById("discovery-status");
    const inventory = document.getElementById("network-candidates");
    const preview = document.getElementById("scope-preview");
    const refresh = document.getElementById("refresh-discovery");
    if (!status || !inventory || !preview || !refresh) return;
    const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"}[char]));
    const candidateKey = (candidate) => `${candidate.interface}|${candidate.local_address}|${candidate.ipv4_cidr}`;
    let activeCandidate = null;

    const discoverHosts = (token, network) => {
        const button = document.getElementById("discover-hosts");
        const output = document.getElementById("host-discovery-result");
        if (!button || !output) return;
        button.disabled = true;
        button.setAttribute("aria-busy", "true");
        output.textContent = `Discovering responding hosts in ${network}…`;
        fetch("/scan/hosts/discover", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({confirmation_token: token})})
            .then((response) => response.json().then((data) => ({ok: response.ok, data})))
            .then(({ok, data}) => {
                if (!ok || !data.ok) throw new Error(data.error || "Host discovery failed.");
                const result = data.result;
                const hosts = result.hosts.length ? `<ul>${result.hosts.map((host) => `<li><code>${escapeHtml(host)}</code> responding</li>`).join("")}</ul>` : "<p>No responding hosts were discovered.</p>";
                const local = result.local_addresses.length ? result.local_addresses.map((address) => `<code>${escapeHtml(address)}</code>`).join(", ") : "none reported";
                output.innerHTML = `<p><strong>${result.hosts.length} responding host${result.hosts.length === 1 ? "" : "s"}</strong> in <code>${escapeHtml(result.network)}</code></p>${hosts}<p class="field-help">Local interface addresses excluded: ${local}</p><p class="field-help">${escapeHtml(result.warning)}</p>`;
            })
            .catch((error) => { output.innerHTML = `<p class="alert alert-error" role="alert">${escapeHtml(error.message)}</p>`; })
            .finally(() => { button.disabled = false; button.removeAttribute("aria-busy"); });
    };

    const confirmScope = (token) => {
        fetch("/scan/scope/preview", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({scope_token: token, confirm: true})})
            .then((response) => response.json().then((data) => ({ok: response.ok, data})))
            .then(({ok, data}) => {
                const message = document.getElementById("scope-confirmation");
                if (!ok || !data.ok) throw new Error(data.error || "Scope confirmation failed.");
                message.textContent = data.message;
                message.insertAdjacentHTML("afterend", `<button class="button button-secondary" type="button" id="discover-hosts">Discover hosts in ${escapeHtml(data.scope.ipv4_cidr)}</button><div id="host-discovery-result" class="host-discovery-result" role="status" aria-live="polite"></div>`);
                document.getElementById("discover-hosts").addEventListener("click", () => discoverHosts(data.confirmation_token, data.scope.ipv4_cidr));
            })
            .catch((error) => { const message = document.getElementById("scope-confirmation"); if (message) message.textContent = error.message; });
    };

    const showPreview = (candidate) => {
        activeCandidate = candidate;
        preview.hidden = false;
        preview.innerHTML = `<p class="eyebrow">Scope preview</p><p>Previewing <code>${escapeHtml(candidate.ipv4_cidr)}</code> on <code>${escapeHtml(candidate.interface)}</code>…</p>`;
        fetch("/scan/scope/preview", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(candidate)})
            .then((response) => response.json().then((data) => ({ok: response.ok, data})))
            .then(({ok, data}) => {
                if (!ok || !data.ok) throw new Error(data.error || "Scope preview failed.");
                const scope = data.scope;
                preview.innerHTML = `<p class="eyebrow">Scope preview</p><p><strong>${escapeHtml(scope.ipv4_cidr)}</strong> · ${scope.host_count} proposed IPv4 targets · excluding ${escapeHtml(scope.local_address)}</p><ul>${scope.warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join("")}</ul><button class="button button-secondary" type="button" id="confirm-scope">Confirm authorized scope</button><p id="scope-confirmation" class="field-help"></p>`;
                document.getElementById("confirm-scope").addEventListener("click", () => confirmScope(data.scope_token));
            })
            .catch((error) => { preview.innerHTML = `<p class="alert alert-error" role="alert">${escapeHtml(error.message)}</p>`; });
    };

    const addressMarkup = (address, candidate) => {
        const isV4 = address.address.includes(".");
        const state = address.eligible ? "Eligible for scope preview" : "Not assessable";
        return `<li><div><span class="inventory-family">${isV4 ? "IPv4" : "IPv6"}</span><code>${escapeHtml(address.address)}/${escapeHtml(address.prefix_length)}</code><small>network ${escapeHtml(address.network)}</small><small class="address-state ${address.eligible ? "is-good" : "is-warning"}">${escapeHtml(state)} · ${escapeHtml(address.eligibility_reason)}</small></div></li>`;
    };

    const renderInventory = (discovery) => {
        const found = discovery.candidates || [];
        const interfaces = discovery.interfaces || [];
        if (!interfaces.length) { inventory.innerHTML = "<div class=\"empty-inventory\">No local network interfaces were returned.</div>"; return; }
        inventory.innerHTML = interfaces.map((item) => {
            const ipv4 = item.ipv4_addresses || [];
            const ipv6 = item.ipv6_addresses || [];
            const addresses = [...ipv4, ...ipv6];
            const primary = ipv4[0];
            const primaryCandidate = primary && found.find((entry) => entry.interface === item.name && entry.local_address === primary.address && entry.ipv4_cidr === primary.network);
            const primaryText = primary ? `<code>${escapeHtml(primary.address)}/${escapeHtml(primary.prefix_length)}</code><small>${escapeHtml(primary.network)}</small>` : "<small>No IPv4 address assigned</small>";
            const eligible = primaryCandidate && primaryCandidate.eligible;
            const reason = primary && !primary.eligible ? primary.eligibility_reason : "";
            const rows = addresses.map((address) => {
                const candidate = found.find((entry) => entry.interface === item.name && entry.local_address === address.address && entry.ipv4_cidr === address.network);
                return addressMarkup(address, candidate);
            }).join("");
            const routes = (item.routes || []).map((route) => `<li><code>${escapeHtml(route)}</code></li>`).join("") || "<li>None reported</li>";
            const issues = (item.issues || []).map((issue) => `<p class="interface-issue">${escapeHtml(issue.message)}</p>`).join("");
            const previewAction = primaryCandidate && primaryCandidate.eligible ? `<button class="button button-secondary interface-preview" type="button" data-candidate-key="${escapeHtml(candidateKey(primaryCandidate))}">Preview scope</button>` : "";
            return `<details class="network-interface"><summary class="interface-summary"><div><strong>${escapeHtml(item.name)}</strong><span class="interface-state ${item.operational_state.toLowerCase() === "up" ? "is-up" : "is-down"}">${escapeHtml(item.operational_state)}</span></div><div class="interface-primary">${primaryText}</div><span class="eligibility ${eligible ? "is-eligible" : "is-ineligible"}">${eligible ? "Eligible" : "Inventory only"}</span>${previewAction}<span class="expand-mark" aria-hidden="true">+</span></summary><div class="interface-details"><div class="interface-details-grid"><div class="detail-group"><h4>Assigned addresses</h4><ul class="address-list">${rows || "<li>No assigned addresses.</li>"}</ul></div><div class="detail-group"><h4>Routes &amp; gateway</h4><ul class="route-list">${item.gateway ? `<li>Gateway <code>${escapeHtml(item.gateway)}</code></li>` : "<li>Gateway not reported</li>"}${routes}</ul></div></div>${reason ? `<p class="interface-issue">${escapeHtml(reason)}</p>` : ""}${issues}</div></details>`;
        }).join("");
        inventory.querySelectorAll("[data-candidate-key]").forEach((button) => button.addEventListener("click", (event) => {
            event.preventDefault();
            const candidate = found.find((entry) => candidateKey(entry) === button.dataset.candidateKey);
            if (candidate) showPreview(candidate);
        }));
    };

    const loadDiscovery = () => {
        const previousKey = activeCandidate && candidateKey(activeCandidate);
        refresh.disabled = true;
        refresh.setAttribute("aria-busy", "true");
        status.textContent = "Reading local interface configuration…";
        fetch("/api/network/discovery")
            .then((response) => response.json().then((data) => ({ok: response.ok, data})))
            .then(({ok, data}) => {
                if (!ok || !data.ok) throw new Error(data.error || "Local discovery is unavailable.");
                renderInventory(data.discovery);
                const eligible = (data.discovery.candidates || []).filter((candidate) => candidate.eligible);
                status.textContent = eligible.length ? "Select an eligible IPv4 network to preview its scope." : "No eligible IPv4 networks were found.";
                if (previousKey) {
                    const current = (data.discovery.candidates || []).find((candidate) => candidateKey(candidate) === previousKey && candidate.eligible);
                    if (current) showPreview(current); else { activeCandidate = null; preview.hidden = true; status.textContent += " The previous scope preview was cleared because interface data changed."; }
                }
            })
            .catch((error) => { status.textContent = `${error.message} Manual individual-IP scanning remains available above.`; })
            .finally(() => { refresh.disabled = false; refresh.removeAttribute("aria-busy"); });
    };
    refresh.addEventListener("click", loadDiscovery);
    loadDiscovery();
});
