- [x] progress bars (those fancy ones)
- [ ] file downloading
- [x] noupload flag that just saves encrypted file to disk
- [x] dry run flag
- [ ] check if file exists before creating and removing (give an `file 'filename.txt' exists. overwrite? [N/y] `)

```
options (downloading):
usage: v8p -r [options] <alias or filename>
  --retrieve,   -r               retrieve a file instead of uploading

  general:
    --server,   -s <url>         set custom server instead of default (https://v8p.me)

  download behavior:
    --local,    -l               instead of an alias, accept a file to decrypt locally
    --filename, -f <name>
```
