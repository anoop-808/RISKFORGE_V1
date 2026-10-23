document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("scan-form");
    if (!form) return;

    form.addEventListener("submit", () => {
        const button = form.querySelector("button[type='submit']");
        if (!button) return;
        button.disabled = true;
        button.classList.add("is-loading");
        button.setAttribute("aria-busy", "true");
    });
});
