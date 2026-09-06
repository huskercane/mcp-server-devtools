// Optional local script check: node tests/console_upload_script_test.cjs.
// No npm packages and no Node requirement in the Cargo/build/CI pipeline.
// A minimal DOM harness tests byte handling, not browser integration.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(`${__dirname}/../console/static/policy-upload.js`, "utf8");
const file = (bytes) => ({size: bytes.length, arrayBuffer: async () => Uint8Array.from(bytes).buffer});
async function submit(policy, signature, pasted = "") {
    let handler, submitted = 0, prevented = false;
    const button = {disabled: false};
    const form = {elements: {bundle: {value: pasted}}, addEventListener: (_, f) => {handler = f;}, querySelector: () => button};
    const error = {textContent: ""};
    const elements = {"signed-policy": form, "policy-file": {files: policy ? [policy] : []}, "signature-file": {files: signature ? [signature] : []}, "upload-error": error};
    vm.runInNewContext(source, {document: {getElementById: id => elements[id]}, TextDecoder, HTMLFormElement: {prototype: {submit() {submitted++;}}}});
    await handler({preventDefault() {prevented = true;}});
    return {submitted, prevented, value: form.elements.bundle.value, error: error.textContent, disabled: button.disabled};
}
(async () => {
    const policy = Buffer.from("\ufeffversion: 2\r\nrules: []\n# é </textarea> & +\n\n");
    const signature = Buffer.from("detached-base64==\n");
    const good = await submit(file(policy), file(signature));
    assert.equal(good.submitted, 1);
    assert.equal(good.prevented, true);
    const body = JSON.parse(good.value);
    assert.deepEqual(Buffer.from(body.document), policy);
    assert.deepEqual(Buffer.from(body.signature), signature);
    assert.equal(good.error, "");
    for (const [a, b] of [[file(policy), null], [null, file(signature)], [file([0xff]), file(signature)], [{size: 256 * 1024 + 1}, file(signature)], [file(policy), {size: 1025}]]) {
        const result = await submit(a, b);
        assert.equal(result.submitted, 0);
        assert.equal(result.prevented, true);
        assert.notEqual(result.error, "");
    }
    const pasted = await submit(null, null, '{"document":"x","signature":"y"}');
    assert.equal(pasted.prevented, false);
    assert.equal(pasted.value, '{"document":"x","signature":"y"}');
    console.log("PASS: exact signed bytes, BOM/CRLF/non-ASCII, invalid UTF-8, missing/oversized files, JSON fallback");
})().catch(error => { console.error(error); process.exitCode = 1; });
