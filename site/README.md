# conU Static Download Page

This folder contains the static conU download page.

Open locally:

```sh
python -m http.server 4173 --directory site
```

Then visit:

```txt
http://127.0.0.1:4173
```

Deploy options:

- Vercel: set the project root to `site/` and use no build command. `site/vercel.json` includes static cache headers.
- Render static site: set the publish directory to `site/`.
- Any static host: upload `index.html` and `styles.css`.

The page is intentionally minimal: black-and-white home screen, download link,
and install command only.
