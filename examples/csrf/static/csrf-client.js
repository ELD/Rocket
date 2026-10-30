const CSRF_ERROR_HEADER = "X-Rocket-CSRF";
const CSRF_ERROR_VALUE = "csrf-failure";
const XSRF_HEADER = "X-XSRF-TOKEN";

export function createCsrfClient(fetchImpl = (...args) => globalThis.fetch(...args)) {
  let currentToken;
  let bootstrapInFlight;

  async function bootstrapXsrf() {
    if (currentToken) {
      return currentToken;
    }

    if (!bootstrapInFlight) {
      bootstrapInFlight = fetchImpl("/api/bootstrap", {
        credentials: "same-origin",
      }).then(async response => {
        if (!response.ok) {
          throw new Error(`CSRF bootstrap failed (${response.status})`);
        }

        const token = await response.json();
        if (typeof token !== "string") {
          throw new Error("CSRF bootstrap returned an invalid token");
        }

        currentToken = token;
        return token;
      }).finally(() => { bootstrapInFlight = undefined; });
    }

    return bootstrapInFlight;
  }

  async function refreshXsrf(rejectedToken) {
    if (currentToken && currentToken !== rejectedToken) {
      return currentToken;
    }

    currentToken = undefined;
    return bootstrapXsrf();
  }

  async function sendMessage(message) {
    const body = JSON.stringify({ message });
    let token = await bootstrapXsrf();
    const send = () => fetchImpl("/api/message", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        [XSRF_HEADER]: token,
      },
      body,
    });

    let response = await send();
    if (response.status !== 403
        || response.headers.get(CSRF_ERROR_HEADER) !== CSRF_ERROR_VALUE) {
      return response;
    }

    token = await refreshXsrf(token);
    return send();
  }

  return { bootstrapXsrf, sendMessage };
}

export function attachCsrfClient(client, button, output) {
  button.addEventListener("click", async () => {
    try {
      const response = await client.sendMessage("Hello from fetch()");
      output.textContent = response.ok
        ? await response.text()
        : `Request failed (${response.status})`;
    } catch (error) {
      output.textContent = `CSRF/network error: ${error.message}`;
    }
  });
}

if (typeof document !== "undefined") {
  const button = document.getElementById("api-send");
  const output = document.getElementById("api-result");
  if (button && output) {
    attachCsrfClient(createCsrfClient(), button, output);
  }
}
