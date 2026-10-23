document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("scan-form");
    if (!form) return;

    form.addEventListener("submit", () => {
        const button = form.querySelector("button[type='submit']");
        if (!button) return;
        button.disabled = true;
        button.classList.add("is-loading");
        button.setAttribute("aria-busy", "true");
        const statusLabel = document.querySelector("#engine-status .status-label");
        if (statusLabel) statusLabel.textContent = "Scanning...";
    });

    const status = document.getElementById("discovery-status");
    const candidates = document.getElementById("network-candidates");
    const preview = document.getElementById("scope-preview");
    if (!status || !candidates || !preview) return;

    const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"}[char]));
    const showPreview = (candidate) => {
        preview.hidden = false;
        preview.innerHTML = `<p class="eyebrow">Scope preview</p><p>Previewing <code>${escapeHtml(candidate.ipv4_cidr)}</code> on <code>${escapeHtml(candidate.interface)}</code>…</p>`;
        fetch("/scan/scope/preview", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(candidate)})
            .then((response) => response.json().then((body) => ({ok: response.ok, body})))
            .then(({ok, body}) => {
                if (!ok || !body.ok) throw new Error(body.error || "Scope preview failed.");
                const scope = body.scope;
                preview.innerHTML = `<p class="eyebrow">Scope preview</p><p><strong>${escapeHtml(scope.ipv4_cidr)}</strong> · ${scope.host_count} proposed IPv4 targets · excluding ${escapeHtml(scope.local_address)}</p><ul>${scope.warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join("")}</ul><button class="button button-secondary" type="button" id="confirm-scope">Confirm authorized scope</button><p id="scope-confirmation" class="field-help"></p>`;
                document.getElementById("confirm-scope").addEventListener("click", () => confirmScope(body.scope_token, scope));
            })
            .catch((error) => { preview.innerHTML = `<p class="alert alert-error" role="alert">${escapeHtml(error.message)}</p>`; });
    };
    const confirmScope = (token, scope) => {
        fetch("/scan/scope/preview", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({scope_token: token, confirm: true})})
            .then((response) => response.json().then((body) => ({ok: response.ok, body})))
            .then(({ok, body}) => {
                const message = document.getElementById("scope-confirmation");
                if (!ok || !body.ok) throw new Error(body.error || "Scope confirmation failed.");
                message.textContent = body.message;
            })
            .catch((error) => { document.getElementById("scope-confirmation").textContent = error.message; });
    };
    fetch("/api/network/discovery")
        .then((response) => response.json().then((body) => ({ok: response.ok, body})))
        .then(({ok, body}) => {
            if (!ok || !body.ok) throw new Error(body.error || "Local discovery is unavailable.");
            const found = body.discovery.candidates;
            status.textContent = found.length ? "Select a discovered IPv4 network to preview its scope." : "No eligible IPv4 networks were found.";
            candidates.innerHTML = found.map((candidate, index) => `<article class="network-candidate"><div><strong>${escapeHtml(candidate.interface)}</strong><span>${escapeHtml(candidate.local_address)} · ${escapeHtml(candidate.ipv4_cidr)}</span><small>${escapeHtml(candidate.operational_state)}${candidate.gateway ? ` · gateway ${escapeHtml(candidate.gateway)}` : ""}</small>${candidate.issues.map((issue) => `<small class="warning">${escapeHtml(issue.message)}</small>`).join("")}</div><button class="button button-secondary" type="button" data-candidate="${index}" ${candidate.eligible ? "" : "disabled"}>Preview scope</button></article>`).join("");
            candidates.querySelectorAll("[data-candidate]").forEach((button) => button.addEventListener("click", () => showPreview(found[button.dataset.candidate])));
        })
        .catch((error) => { status.textContent = error.message; candidates.innerHTML = "<p class=\"field-help\">Manual individual-IP scanning remains available above.</p>"; });
});
