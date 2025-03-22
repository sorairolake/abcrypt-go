<!--
SPDX-FileCopyrightText: 2024 Shun Sakai

SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# abcrypt-go

[![CI][ci-badge]][ci-url]
[![Go Reference][reference-badge]][reference-url]
![Go version][go-version-badge]

**abcrypt-go** is an implementation of the [abcrypt encrypted data format].

This package supports version 1 of the abcrypt format.

## Usage

To install this library:

```sh
go get -u github.com/sorairolake/abcrypt-go
```

### Documentation

See the [documentation][reference-url] for more details.

## Minimum Go version

This library requires the minimum version of Go 1.23.0.

## Source code

The upstream repository is available at
<https://github.com/sorairolake/abcrypt-go.git>.

The source code is also available at:

- <https://gitlab.com/sorairolake/abcrypt-go.git>
- <https://codeberg.org/sorairolake/abcrypt-go.git>

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## License

Copyright (C) 2024 Shun Sakai (see [AUTHORS.adoc])

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.3 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt-go/CI.yaml?branch=develop&style=for-the-badge&logo=github&label=CI
[ci-url]: https://github.com/sorairolake/abcrypt-go/actions?query=branch%3Adevelop+workflow%3ACI++
[reference-badge]: https://img.shields.io/badge/Go-Reference-steelblue?style=for-the-badge&logo=go
[reference-url]: https://pkg.go.dev/github.com/sorairolake/abcrypt-go
[go-version-badge]: https://img.shields.io/github/go-mod/go-version/sorairolake/abcrypt-go?style=for-the-badge&logo=go
[abcrypt encrypted data format]: https://sorairolake.github.io/abcrypt/book/format.html
[CHANGELOG.adoc]: CHANGELOG.adoc
[CONTRIBUTING.adoc]: CONTRIBUTING.adoc
[AUTHORS.adoc]: AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec/
