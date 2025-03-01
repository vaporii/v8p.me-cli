# v8p.me-cli

a cli tool for uploading files for v8p.me

### installation

dependencies:

- git
- go >= 1.24.0
- xsel, xclip, or wl-clipboard (Linux only)

```bash
git clone https://github.com/vaporii/v8p.me-cli
cd v8p.me-cli

go mod tidy
go build -o v8p
```

then, you can move the `v8p` executable anywhere you'd like and/or add the following to your .zshrc or .bashrc (replacing `/path/to/executable` with the directory containing your executable):

`export PATH="/path/to/executable:$PATH"`

### usage

```
v8p [arguments] <filename>

arguments:
--password, -p <password>    enable encryption and set password
--expires,  -e <date str>    set expiry date of file (-e 1d), (-e 3weeks), (--expires \"5 minutes\")
--copy,     -c               if present, automatically copy returned URL to clipboard
--server,   -s <url>         direct requests to custom server instead of default (https://v8p.me) (-s https://example.com)

examples:
v8p -c -p Password123! -e \"5 days\" image.png
v8p --copy --password=\"Cr3d3nt1a1$\" text.txt
v8p -e 1h -c video.mkv
```
