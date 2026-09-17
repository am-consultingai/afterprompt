// Afterprompt site: copy button.
// The page is complete without this file.
(function () {
  "use strict";

  document.querySelectorAll("button[data-copy]").forEach(function (btn) {
    if (!navigator.clipboard) return;
    var label = btn.querySelector("span");
    btn.hidden = false;
    btn.addEventListener("click", function () {
      var text = document.getElementById(btn.dataset.copy).textContent.trim();
      navigator.clipboard.writeText(text).then(function () {
        label.textContent = "Copied";
      }, function () {
        label.textContent = "Select to copy";
      });
      setTimeout(function () { label.textContent = "Copy"; }, 1600);
    });
  });
})();
