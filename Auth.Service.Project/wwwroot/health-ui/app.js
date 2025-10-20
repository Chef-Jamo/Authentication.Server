async function fetchHealth() {
  try {
    const res = await fetch("/health");
    const json = await res.json();
    render(json);
  } catch (err) {
    document.getElementById("status").textContent = "Unavailable";
    document.getElementById("status").className = "status Unhealthy";
    document.getElementById("raw").textContent = String(err);
  }
}

function render(json) {
  const statusEl = document.getElementById("status");
  statusEl.textContent = json.status;
  statusEl.className = "status " + (json.status || "unknown");

  const checksEl = document.getElementById("checks");
  checksEl.innerHTML = "";
  (json.checks || []).forEach((c) => {
    const li = document.createElement("li");
    li.innerHTML = `<span>${c.name}</span><span>${c.status}</span>`;
    checksEl.appendChild(li);
  });

  document.getElementById("raw").textContent = JSON.stringify(json, null, 2);
}

fetchHealth();
setInterval(fetchHealth, 5000);
