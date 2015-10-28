matasano
========

Solutions to the matasano crypto challenges in ruby.


## Running tests
Some of the modules have spec files which can be run using `bacon`. Sample
output:

```
❯❯❯ bacon *_spec.rb
AES
  - ecrypts data correctly
  - decrypts data correctly
  - does sub_bytes correctly
  - does sub_bytes_inv correctly
  - does shift_rows correctly
  - does shift_rows_inv correctly
  - does mix_cols correctly
  - does mix_cols_inv correctly
  - does add_round_key correctly

9 specifications (9 requirements), 0 failures, 0 errors
```
