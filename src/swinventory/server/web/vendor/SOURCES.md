# Self-hosted AdminLTE CSS

Prepared 2026-11-23 from the locally verified official npm package extraction recorded in the visual audit vendor manifest. The upstream stylesheet and license text are copied without modification. Package scripts and build hooks were not run.

## Pinned source and integrity

- AdminLTE `admin-lte@4.10.2`: https://registry.npmjs.org/admin-lte/-/admin-lte-4.10.2.tgz
  - npm `dist.integrity`: `sha512-Od12qdK1c2pJa+JO8YJiX85M64o8ZieMqoJHTbeoIcrgB/YXD7mILAH7hfcPFBOZVHD7qniogMvTtRZ9H7/YAA==`
  - source tarball SHA-256: `679f1bf1b8195737be3ce56954870caa96586748368c5b6306489b7423ea3039`
  - included stylesheet SHA-256: `b31e1aaac260f9d406b1f9ec28dbbb75ad57bc82bd3334e67d854425e78b7c0e`
- Bootstrap `bootstrap@5.3.9` is included within the AdminLTE stylesheet; it is not loaded separately. Its package tarball SHA-256 is `06bdf78289c3c12ea99d40df84eedf6278c724c73eebf38f11f3a65b44ec8c94`.

## Runtime and licenses

Only the original `admin-lte/4.10.2/dist/css/adminlte.min.css` stylesheet is used at runtime; it is copied unchanged to `admin-lte/4.10.2/css/adminlte.min.css` so Git's generic `dist/` ignore rule does not omit the runtime asset. It includes Bootstrap CSS, so no duplicate Bootstrap stylesheet is loaded. No JavaScript, Popper runtime, external fonts, images, or charts are shipped. The preserved license texts are `admin-lte/4.10.2/LICENSE` (MIT, ColorlibHQ) and `bootstrap/5.3.9/LICENSE` (MIT, The Bootstrap Authors).
