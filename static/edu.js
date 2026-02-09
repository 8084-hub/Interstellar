const form = document.querySelector("#proxy-form");
const urlInput = document.querySelector("#url-input");
const statusText = document.querySelector("#status-text");
const statusBox = document.querySelector(".status");
const iframe = document.querySelector("#preview-frame");
const overlay = document.querySelector("#frame-overlay");
const targetLink = document.querySelector("#target-link");
const button = document.querySelector("#go-button");

const setStatus = (message, isError = false) => {
  statusText.textContent = message;
  statusBox.classList.toggle("error", isError);
};

const setLoading = isLoading => {
  overlay.classList.toggle("active", isLoading);
  button.disabled = isLoading;
};

const sanitizeInput = value => value.replace(/\s+/g, "").trim();

form.addEventListener("submit", async event => {
  event.preventDefault();
  const raw = sanitizeInput(urlInput.value);

  if (!raw) {
    setStatus("Please enter an HTTPS URL.", true);
    return;
  }

  setLoading(true);
  setStatus("Fetching page via the server-side proxy...");
  targetLink.textContent = raw;
  targetLink.href = raw;
  iframe.srcdoc = "";

  try {
    const response = await fetch("/api/proxy", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: raw }),
    });

    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Unable to fetch that page.");
    }

    // The iframe is sandboxed (no scripts) so even if the HTML contains scripts,
    // they won't execute. This keeps the demo safe while still showing content.
    iframe.srcdoc = payload.html;
    setStatus("Loaded. The HTML is rendered in the sandboxed frame.");
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    setLoading(false);
  }
});
