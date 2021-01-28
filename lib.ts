async function fetchWithTimeout(resource, options) {
    const { timeout = -1, abortCB = undefined } = options;

    const controller = new AbortController();
    if (abortCB) abortCB(controller);
    let id;
    if (timeout !== -1) id = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(resource, {
        ...options,
        signal: controller.signal
    });
    if (timeout !== -1) clearTimeout(id);

    return response;
}
