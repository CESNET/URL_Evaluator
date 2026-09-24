  function showFilter() {
    const filters = document.getElementById('filters');
    if (filters.classList.contains('active-filter')) {
      filters.classList.remove('active-filter');
    } else {
      filters.classList.add('active-filter')
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

    const currentUrl = window.location.pathname;
    var resultUrl = currentUrl + "detail?url=" + encodeURIComponent(element.value);
    const div = document.createElement('div');
    div.className = 'selected-url';
    div.innerHTML = `
      <input type="hidden" name="selected_urls_list[]" value="${element.value}">
      <a href="${resultUrl}" target="_blank"><span>${element.value}</span></a>
      <button type="button" onclick="removeSelectedURLElement(this)">X</button>
    `;
    wrap.appendChild(div);
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
              const currentUrl = window.location.pathname;
              var resultUrl = currentUrl + "detail?url=" + encodeURIComponent(list[i]);
              const div = document.createElement('div');
              div.className = 'selected-url';
              div.innerHTML = `
                  <input type="hidden" name="selected_urls_list[]" value="${list[i]}">
                  <a href="${resultUrl}" target="_blank"><span>${list[i]}</span></a>
                  <button type="button" onclick="removeSelectedURLElement(this)">X</button>
              `;
              wrap.appendChild(div);
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

// ----------------------------------------------------------------

function toggleHelp(element) {
    var x = element.querySelector(".help-content");
    if (x.style.display === "none") {
      x.style.display = "block";
    } else {
      x.style.display = "none";
    }
}

// ----------------------------------------------------------------
// Quick URL search (top panel) - live results while typing
// ----------------------------------------------------------------
(function () {
  var DEBOUNCE_MS = 200;
  var AMP = String.fromCharCode(38);

  function escapeHtml(s) {
    return String(s)
      .split('&').join(AMP + 'amp;')
      .split('<').join(AMP + 'lt;')
      .split('>').join(AMP + 'gt;')
      .split('"').join(AMP + 'quot;')
      .split("'").join(AMP + '#39;');
  }

  function initQuickSearch() {
    var input = document.getElementById('quick-url-search');
    var resultsBox = document.getElementById('quick-search-results');
    if (!input || !resultsBox) return;

    var debounceTimer = null;
    var activeIndex = -1;
    var currentResults = [];

    function hideResults() {
      resultsBox.style.display = 'none';
      resultsBox.innerHTML = '';
      activeIndex = -1;
      currentResults = [];
    }

    function highlightMatch(url, query) {
      var idx = url.toLowerCase().indexOf(query.toLowerCase());
      if (idx === -1) return escapeHtml(url);
      return escapeHtml(url.slice(0, idx)) +
             '<mark>' + escapeHtml(url.slice(idx, idx + query.length)) + '</mark>' +
             escapeHtml(url.slice(idx + query.length));
    }

    function renderResults(results, query) {
      currentResults = results;
      activeIndex = -1;
      if (!results.length) {
        resultsBox.innerHTML = '<div class="qs-item qs-empty">No matching URLs</div>';
        resultsBox.style.display = 'block';
        return;
      }
      resultsBox.innerHTML = results.map(function (r, i) {
        var cls = (r.classification || 'unclassified');
        return '<div class="qs-item" data-index="' + i + '" data-url="' + escapeHtml(r.url) + '">' +
               '<span class="qs-url">' + highlightMatch(r.url, query) + '</span>' +
               '<span class="qs-badge qs-' + escapeHtml(cls) + '">' + escapeHtml(cls) + '</span>' +
               '</div>';
      }).join('');
      resultsBox.style.display = 'block';
    }

    function goToDetail(url) {
      var params = new URLSearchParams({ url: url });
      var show = new URLSearchParams(window.location.search).get('show');
      if (show) params.set('show', show);
      window.location.href = '/detail?' + params.toString();
    }

    function setActive(index) {
      var items = resultsBox.querySelectorAll('.qs-item:not(.qs-empty)');
      items.forEach(function (el) { el.classList.remove('qs-active'); });
      if (index >= 0 && index < items.length) {
        activeIndex = index;
        items[index].classList.add('qs-active');
        items[index].scrollIntoView({ block: 'nearest' });
      } else {
        activeIndex = -1;
      }
    }

    input.addEventListener('input', function () {
      var q = input.value.trim();
      clearTimeout(debounceTimer);
      if (!q) {
        hideResults();
        return;
      }
      debounceTimer = setTimeout(function () {
        fetch('/api/search_url?q=' + encodeURIComponent(q))
          .then(function (resp) { return resp.ok ? resp.json() : { results: [] }; })
          .then(function (data) { renderResults(data.results || [], q); })
          .catch(function () { hideResults(); });
      }, DEBOUNCE_MS);
    });

    input.addEventListener('keydown', function (e) {
      var items = resultsBox.querySelectorAll('.qs-item:not(.qs-empty)');
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActive(Math.min(activeIndex + 1, items.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActive(Math.max(activeIndex - 1, -1));
      } else if (e.key === 'Enter') {
        if (activeIndex >= 0 && currentResults[activeIndex]) {
          goToDetail(currentResults[activeIndex].url);
        } else if (currentResults.length > 0) {
          goToDetail(currentResults[0].url);
        }
      } else if (e.key === 'Escape') {
        hideResults();
        input.blur();
      }
    });

    resultsBox.addEventListener('mousedown', function (e) {
      // mousedown (not click) so it fires before blur hides the dropdown
      var item = e.target.closest('.qs-item:not(.qs-empty)');
      if (item) {
        e.preventDefault();
        goToDetail(item.dataset.url);
      }
    });

    input.addEventListener('blur', function () {
      // small delay so mousedown on a result can fire first
      setTimeout(hideResults, 150);
    });

    input.addEventListener('focus', function () {
      if (input.value.trim() && currentResults.length) {
        resultsBox.style.display = 'block';
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initQuickSearch);
  } else {
    initQuickSearch();
  }
})();
