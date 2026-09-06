// Native file selection only; all validation, rendering and mutations stay
// server-side. JSON escapes keep signed newlines out of form normalization.
"use strict";
const upload = document.getElementById("signed-policy");
upload.addEventListener("submit", async (event) => {
    const policy = document.getElementById("policy-file").files[0];
    const signature = document.getElementById("signature-file").files[0];
    if (!policy && !signature) return; // JSON / no-script form uses the same route.
    event.preventDefault();
    const error = document.getElementById("upload-error");
    if (!policy || !signature) {
        error.textContent = "Select both the policy and detached signature files.";
        return;
    }
    // Bound memory before reading; the server and admin API impose their own bounds.
    if (policy.size > 256 * 1024 || signature.size > 1024) {
        error.textContent = "Policy must be at most 256 KiB and signature at most 1 KiB.";
        return;
    }
    const button = upload.querySelector("button[type=submit]");
    button.disabled = true;
    try {
        // Keep a UTF-8 BOM if present and reject malformed UTF-8, never replace it.
        const decoder = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true});
        const document = decoder.decode(await policy.arrayBuffer());
        const detached = decoder.decode(await signature.arrayBuffer());
        upload.elements.bundle.value = JSON.stringify({document, signature: detached});
        HTMLFormElement.prototype.submit.call(upload);
    } catch {
        error.textContent = "Could not read UTF-8 files. No policy was submitted.";
        button.disabled = false;
    }
});
