# TOOLS

## asci2html Usage:
`asci2html` will create an html file of your console output that you can use to share examples, results and do disconnected demos. It supports both 
a `light` and `dark` background (dark seems to work best for inspec runs).  

```
➜  tools git:(master) ✗ ./ansi2html.sh --help
This utility converts ANSI codes in data passed to stdin
It has 4 optional parameters:
--bg=dark --palette=linux|solarized|tango|xterm --css-only|--body-only
E.g.: ls -l --color=always | ansi2html.sh --bg=dark > ls.html
```
### EXAMLE
  - `postgresql-baseline git:(master) ✗ inspec exec controls/. -i $SSH_KEY_H -t ssh://vagrant@127.0.0.1:2222 | ./ansi2html.sh --bg=dark > test2.html`

