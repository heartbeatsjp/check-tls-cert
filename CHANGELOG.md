# ChangeLog

## 0.6.0 (2021-10-18)

### Feature

- Add shell completion [#26]

### Fixed

- Verify the certificate of the OCSP authorized responder [#28]

## 0.5.1 (2021-09-24)

### Fixed

- If the post-encapsulation boundary in PEM file does not have EOL, an error will occur.

## 0.5.0 (2021-09-22)

### Feature

- Add --tls-min-version option [#23]
- Support go 1.17 [#22]

## 0.4.3 (2021-09-09)

### Fixed

- If there is an empty line at the end of the PEM file, a panic will occur. [#20]

## 0.4.2 (2021-07-24)

### Fixed

- Fix an OCSP-related issue [#19]

## 0.4.1 (2021-07-13)

### Fixed

- Remove an unnecessary log output [#18]
- Fix comments [#17]

## 0.4.0 (2021-07-13)

- First public release
