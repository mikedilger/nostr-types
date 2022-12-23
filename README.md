# nostr-types

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Docs.rs][doc-badge]][doc-url]
[![Temp Docs][doc2-badge]][doc2-url]

[crates-badge]: https://img.shields.io/crates/v/nostr-types.svg
[crates-url]: https://crates.io/crates/nostr-types
[doc-badge]: https://img.shields.io/badge/docs.rs-green.svg
[doc-url]: https://docs.rs/nostr-types
[doc2-badge]: https://img.shields.io/badge/tempdocs-green.svg
[doc2-url]: https://mikedilger.com/docs/nostr-types/nostr_types/
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/mikedilger/nostr-types/blob/master/LICENSE-MIT

nostr-types is a crate defining types useful for the nostr protocol.

We wrap all basic types. An `i64` may or may not be a `Unixtime`. A `&str` might
be a hex encoded private key, or it might be somebody's name. By using types for
everything, common mistakes can be avoided.

We have extensive serde implementations for all types which are not simple to serialize
such as Tag.

Private keys remember if you've seen them or imported them and set themselves to `Weak` if
you have. Generated private keys start out as `Medium`.  We don't support `Strong` yet
which will require a hardware token. (Note: there are ways to leak a private key without
it knowing, so if it says `Medium` that is the maximum security, not a guaranteed level
of security). Private keys can be imported and exported in a password-keyed encrypted form
without weakening their security.

## Progress

Basic functionality is coded for the following NIPs. Be aware that we only provide types,
so a lot of NIP content is not applicable.


- [x] NIP-01
- [x] NIP-02
- [ ] NIP-03 - OpenTimestamps are low priority
- [ ] NIP-04 - Will not support. Do not recommend.
- [x] NIP-05
- [ ] NIP-06 - Not interesting to me, not being a bitcoiner; low priority
- [x] NIP-07 - n/a
- [ ] NIP-08 - TBD
- [x] NIP-09 - mostly n/a but supported where applicable
- [x] NIP-10 - mostly n/a but supported where applicable
- [x] NIP-11
- [ ] NIP-12 - TBD
- [ ] NIP-13 - TBD
- [x] NIP-14
- [ ] NIP-15 - n/a
- [x] NIP-16
- [x] NIP-19 - supported for keys only
- [x] NIP-20 - mostly n/a but supported where applicable
- [x] NIP-22 - n/a
- [x] NIP-25 - mostly n/a but supported where applicable
- [ ] NIP-26 - TBD, can be done manually currently.
- [ ] NIP-28 - Partially. EventKind recognizes, them but content handling not there.
- [x] NIP-35 - n/a
- [x] NIP-36 - mostly n/a but supported where applicable
- [x] NIP-40 - mostly n/a but supported where applicable

## License

 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, shall be licensed as above, without any additional
terms or conditions.
