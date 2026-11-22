# Chart.js (optional local copy)

The app loads Chart.js from `chart.umd.min.js` in this folder first, then falls back to the pinned CDN
version 4.4.1 on cdnjs. To run fully offline, download
https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js
and save it here as `chart.umd.min.js`. If neither source loads, the app still works: charts are replaced by a note
and all numbers remain in the tables.
