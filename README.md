# v8p.me-cli

a cli tool for encrypting and uploading files for v8p.me

![demo](https://github.com/user-attachments/assets/dda4d2a2-5ac3-4586-ae47-757c1daee107)

### installation

dependencies:

- git
- go >= 1.24.0
- xsel, xclip, or wl-clipboard (Linux only)

```bash
git clone https://github.com/vaporii/v8p.me-cli
cd v8p.me-cli

go mod tidy
go build -o build/v8p
```

then, you can move the `v8p` executable anywhere you'd like and/or add the following to your .zshrc or .bashrc (replacing `/path/to/executable/build` with the directory containing your executable):

`export PATH="/path/to/executable/build:$PATH"`

### usage

```
usage: v8p [options] <filename>

options:
  general:
    --server,   -s <url>         set custom server instead of default (https://v8p.me)
    --copy,     -c               automatically copy returned URL to clipboard

  security:
    --password, -p <password>    enable encryption and set password
    --expires,  -e <date str>    set expiry date of file (e.g., -e 1d, -e "5 minutes")

  upload behavior:
    --filename, -f <name>        override filename sent to server
    --dry,      -d <filename>    skip upload and save encrypted file to disk as specified filename

  output control:
    --quiet,    -q               suppress all output except the URL

examples:
v8p -c -p Password123! -e "5 days" image.png
v8p --copy --password="Cr3d3nt1a1$" text.txt
v8p -e 1h -c video.mkv
```
