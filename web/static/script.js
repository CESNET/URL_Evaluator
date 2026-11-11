  function showFilter() {
    const filters = document.getElementById('filters');
    const open = filters.classList.toggle('active-filter');
    const toggle = document.getElementById('filter-toggle');
    if (toggle) {
      toggle.classList.toggle('open', open);
      toggle.setAttribute('aria-expanded', open);
    }
  }

  function showSelect() {
    const filters = document.getElementsByClassName('select');

    if (filters[0].classList.contains('active-select')) {
      localStorage.removeItem('selectedURLs');
      localStorage.removeItem('selectActive');
    }

    for (let i = 0; i < filters.length; i++) {
      if (filters[i].classList.contains('active-select')) {
        filters[i].classList.remove('active-select');
      } else {
        filters[i].classList.add('active-select')
      }
    }
  }

  function selectCheckboxURL(element) {
    if (element.checked) {
      addSelectedURLElement(element);
    } else {
      removeUncheckedURL(element);
    }
  }

  function removeUncheckedURL(element) {
    url = element.value;
    selected_urls = document.getElementsByName("selected_urls_list[]");
    for (let i = 0; i < selected_urls.length; i++) {
      value = selected_urls[i].value;
      if (value === url) {
        selected_urls[i].parentElement.remove();
      }
    }
  }


  function addSelectedURLElement(element) {
    wrap = document.getElementById('selected-urls-wrap');
    list = document.getElementsByName("selected_urls_list[]")
    for (let i = 0; i < list.length; i++) {
      value = list[i].value;
      if (value === element.value) {
        return;
      }
    }

    wrap.appendChild(selectedURLElement(element.value));
  }

  // One entry of the "Selected URLs" list. Built with the DOM API, never
  // innerHTML: the URLs come from honeypots, i.e. from attackers.
  function selectedURLElement(url) {
    const div = document.createElement('div');
    div.className = 'selected-url';
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'selected_urls_list[]';
    input.value = url;
    const link = document.createElement('a');
    link.href = 'detail?url=' + encodeURIComponent(url);
    const span = document.createElement('span');
    span.textContent = url;
    link.appendChild(span);
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'X';
    button.addEventListener('click', function () { removeSelectedURLElement(button); });
    div.append(input, link, button);
    return div;
  }

  function removeSelectedURLElement(element) {
    url = element.parentElement.querySelector('input').value;
    element.parentElement.remove();
    checkboxes = document.getElementsByName('selected_urls[]');
    for (let i = 0; i < checkboxes.length; i++) {
      if (checkboxes[i].value === url) {
        checkboxes[i].checked = false;
      }
    }
  }

  // Get all checkboxes by class name
  var checkboxes = document.querySelectorAll('input[name="selected_urls[]"]');

  // Loop through each checkbox and attach event listener
  checkboxes.forEach(function(checkbox) {
      checkbox.addEventListener('change', function() {
        selectCheckboxURL(checkbox);
    } );
  });


  function selectAll(source) {
    checkboxes = document.getElementsByName('selected_urls[]');
    for(var i=0, n=checkboxes.length;i<n;i++) {
      checkboxes[i].checked = source.checked;
      checkbox = checkboxes[i];
      selectCheckboxURL(checkbox);
    }
  }

  function saveList() {
    active_select = document.getElementsByClassName('active-select');
    if (!active_select || active_select.length === 0) {
      return;
    }

    list = document.getElementsByName("selected_urls_list[]");
    var urls = [];
    for (let i = 0; i < list.length; i++) {
      urls.push(list[i].value);
    }
  
    var listString = JSON.stringify(urls);

    localStorage.setItem('selectedURLs', listString);
    localStorage.setItem('selectActive', 'true');
    console.log('List saved');
  }

  function loadList() {
      var listString = localStorage.getItem('selectedURLs');

      if (listString) {
          var list = JSON.parse(listString);

          var wrap = document.getElementById('selected-urls-wrap');

          console.log(list.length)
          for (let i = 0; i < list.length; i++) {
              wrap.appendChild(selectedURLElement(list[i]));
          }

          urls = document.getElementsByName('selected_urls[]');
          for (let i = 0; i < urls.length; i++) {
            url = urls[i].value;
            for (let j = 0; j < list.length; j++) {
              if (url === list[j]) {
                urls[i].checked = true;
              }
            }
          }
      }
      localStorage.removeItem('selectedURLs');
      localStorage.removeItem('selectActive');
      console.log('List loaded');
      
  }

  function activeSelect() {
    active = localStorage.getItem('selectActive');
    if (active === 'true') {
      showSelect();
      loadList();
    }
  }

  function showAddURL() {
    const add = document.getElementById('add-url-wrap');
    if (add.classList.contains('active-add')) {
      add.classList.remove('active-add');
    } else {
      add.classList.add('active-add')
    }
  }

  function cancelAddURL() {
    const textarea = document.getElementById('add-url');
    textarea.value = '';
    validateAddURLs();
    document.getElementById('add-url-wrap').classList.remove('active-add');
  }

  // Client-side mirror of common.utils.split_url_lines()
  function splitURLLines(text) {
    return text.split(/[\s,]+/).filter(function (token) { return token; });
  }

  // Client-side mirror of common.utils.is_valid(): urlparse() needs both a
  // scheme and a netloc, i.e. "scheme://host...".
  function isValidURL(url) {
    return /^[a-z][a-z0-9+.\-]*:\/\/[^\/?#]+/i.test(url);
  }

  function escapeHTML(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Validate the add-URL textarea as the user types; report invalid entries
  // right away and keep the submit button disabled until all of them are valid.
  function validateAddURLs() {
    const textarea = document.getElementById('add-url');
    const report = document.getElementById('add-url-check');
    const submit = document.getElementById('add-url-submit');
    if (!textarea || !report || !submit) {
      return;
    }
    const candidates = splitURLLines(textarea.value);
    const invalid = candidates.filter(function (url) { return !isValidURL(url); });
    const valid = candidates.length - invalid.length;

    textarea.classList.toggle('has-invalid', invalid.length > 0);
    submit.disabled = candidates.length === 0 || invalid.length > 0;

    if (candidates.length === 0) {
      report.innerHTML = '';
    } else if (invalid.length === 0) {
      report.innerHTML = '<span class="ok">' + valid + ' valid URL(s) ready to add.</span>';
    } else {
      report.innerHTML = '<span class="err">' + invalid.length + ' invalid URL(s)</span>'
        + ' (' + valid + ' valid). A URL must look like <code>http://host/path</code>:'
        + '<ul>' + invalid.map(function (url) { return '<li>' + escapeHTML(url) + '</li>'; }).join('') + '</ul>';
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    const textarea = document.getElementById('add-url');
    if (!textarea) {
      return;
    }
    textarea.addEventListener('input', validateAddURLs);
    textarea.form.addEventListener('submit', function (event) {
      validateAddURLs();
      if (document.getElementById('add-url-submit').disabled) {
        event.preventDefault();
      }
    });
    validateAddURLs();
  });

  document.addEventListener("DOMContentLoaded", function () {
    setTimeout(function () {
        const targetElement = document.getElementsByClassName("add-response")[0];
        if (targetElement) {
          // targetElement.style.display = "block";
          targetElement.style.opacity = 1;
          targetElement.style.transition = "opacity 1s";
        }
        setTimeout(function () {
            const targetElement = document.getElementsByClassName("add-response")[0];
            if (targetElement) {
              targetElement.style.opacity = 0;
              // targetElement.style.display = "none";
            }
        }, 3000); // Hide the element after 5 seconds
    }, 3000); // Show the element after 5 seconds
  });

  // Live quick URL search: auto-submit the form (debounced) while typing,
  // no Enter needed. Falls back to manual submit when JS is disabled.
  document.addEventListener("DOMContentLoaded", function () {
    const quickSearch = document.getElementById('quick-search');
    if (!quickSearch || !quickSearch.form) {
      return;
    }
    let debounceTimer = null;
    quickSearch.addEventListener('input', function () {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () {
        // Remember that we submitted via live-search so focus can be restored
        // (with caret at the end) after the page reloads.
        sessionStorage.setItem('quickSearchFocus', '1');
        quickSearch.form.submit();
      }, 400); // ms pause between keystrokes before searching
    });

    // After a live-search reload, put focus back into the search field and
    // move the caret behind the last typed character.
    if (sessionStorage.getItem('quickSearchFocus') === '1' && quickSearch.value) {
      sessionStorage.removeItem('quickSearchFocus');
      quickSearch.focus();
      const len = quickSearch.value.length;
      if (quickSearch.setSelectionRange) {
        quickSearch.setSelectionRange(len, len);
      }
    }
  });

// ----------------------------------------------------------------

function toggleHelp(element) {
    var x = element.querySelector(".help-content");
    if (x.style.display === "none") {
      x.style.display = "block";
    } else {
      x.style.display = "none";
    }
}


// Copy the button's data-copy value; the clipboard API needs HTTPS, so fall
// back to execCommand on plain HTTP deployments.
function copyToClipboard(button) {
    var text = button.getAttribute("data-copy");
    var title = button.title;
    var done = function () {
        button.classList.add("copied");
        button.title = "Copied";
        setTimeout(function () {
            button.classList.remove("copied");
            button.title = title;
        }, 1500);
    };
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done);
        return;
    }
    var area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    try {
        if (document.execCommand("copy")) done();
    } finally {
        document.body.removeChild(area);
    }
}

// Close the header "Recent" dropdown when clicking anywhere outside it.
document.addEventListener("click", function (event) {
    document.querySelectorAll("details.recent-urls[open]").forEach(function (menu) {
        if (!menu.contains(event.target)) menu.removeAttribute("open");
    });
});

// Header light/dark switch; the choice is remembered in this browser.
function toggleTheme() {
    var root = document.documentElement;
    var theme = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    root.setAttribute("data-theme", theme);
    try {
        localStorage.setItem("theme", theme);
    } catch (e) {}
}
