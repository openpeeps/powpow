// Tiny client-side script for the powpow static server demo.
const timeEl = document.getElementById("time");
const btn = document.getElementById("btn");

async function loadTime() {
  try {
    const res = await fetch("/api/time");
    const json = await res.json();
    timeEl.textContent = "server time: " + json.time;
  } catch (err) {
    timeEl.textContent = "failed to fetch /api/time: " + err;
  }
}

if (btn) btn.addEventListener("click", loadTime);
loadTime();
