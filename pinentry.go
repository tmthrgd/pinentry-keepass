package main

// go fmt github.com/tmthrgd/pinentry-keepass && go install github.com/tmthrgd/pinentry-keepass && killall gpg-agent && gpg-agent --daemon --debug-level 9 --pinentry-program $(which pinentry-keepass)

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
)

const (
	version = "0.1.0"

	debug = true
)

func respondOK(_ string, out io.Writer) (err error) {
	_, err = io.WriteString(out, "OK\n")
	return
}

func cmdGetInfo(args string, out io.Writer) (err error) {
	switch args {
	case "pid":
		if _, err = fmt.Fprintf(out, "D %d\n", os.Getpid()); err != nil {
			return
		}

		return respondOK(args, out)
	case "version":
		if _, err = fmt.Fprintf(out, "D %s\n", version); err != nil {
			return
		}

		return respondOK(args, out)
	case "flavor":
		if _, err = io.WriteString(out, "D keepass\n"); err != nil {
			return
		}

		return respondOK(args, out)
	default:
		_, err = io.WriteString(out, "ERR Unknown command\n")
		return
	}
}

type context struct {
	KeyInfo string
}

func (ctx *context) CmdKeyInfo(args string, out io.Writer) error {
	ctx.KeyInfo = args
	return respondOK(args, out)
}

func (ctx *context) CmdGetPIN(args string, out io.Writer) (err error) {
	if len(ctx.KeyInfo) == 0 {
		_, err = io.WriteString(out, "ERR Operation cancelled\n")
		return
	}

	// lookup by: ctx.KeyInfo
	pass := os.Getenv("PINENTRY_KEEPASS_PASS")

	if len(pass) == 0 {
		_, err = io.WriteString(out, "ERR Operation cancelled\n")
		return
	}

	if _, err = fmt.Fprintf(out, "D %s\n", pass); err != nil {
		return
	}

	return respondOK(args, out)
}

// https://www.gnupg.org/ftp/gcrypt/pinentry/pinentry-1.0.0.tar.bz2
// https://github.com/Chronic-Dev/libgpg-error/blob/d555c739a934aa2c8f65f38834c950d3cbb11dab/src/err-codes.h.in
// http://info2html.sourceforge.net/cgi-bin/info2html-demo/info2html?(pinentry)Protocol
// https://www.gnupg.org/documentation/manuals/assuan/

func main() {
	stdin, stdout := bufio.NewScanner(os.Stdin), io.Writer(os.Stdout)

	if debug {
		in, err := os.Create("/tmp/stdin.bin")
		if err != nil {
			panic(err)
		}

		out, err := os.Create("/tmp/stdout.bin")
		if err != nil {
			panic(err)
		}

		stdin, stdout = bufio.NewScanner(io.TeeReader(os.Stdin, in)), io.MultiWriter(os.Stdout, out)
	}

	if _, err := io.WriteString(stdout, "OK Your orders please\n"); err != nil {
		panic(err)
	}

	ctx := new(context)
	commands := map[string]func(args string, out io.Writer) error{
		"OPTION":           respondOK,
		"SETDESC":          respondOK,
		"SETPROMPT":        respondOK,
		"SETKEYINFO":       ctx.CmdKeyInfo,
		"SETREPEAT":        respondOK,
		"SETREPEATERROR":   respondOK,
		"SETERROR":         respondOK,
		"SETOK":            respondOK,
		"SETNOTOK":         respondOK,
		"SETCANCEL":        respondOK,
		"GETPIN":           ctx.CmdGetPIN,
		"CONFIRM":          respondOK,
		"MESSAGE":          respondOK,
		"SETQUALITYBAR":    respondOK,
		"SETQUALITYBAR_TT": respondOK,
		"GETINFO":          cmdGetInfo,
		"SETTITLE":         respondOK,
		"SETTIMEOUT":       respondOK,
		"CLEARPASSPHRASE":  respondOK,
		"BYE":              func(string, io.Writer) error { return nil },
	}

	for stdin.Scan() {
		b := stdin.Bytes()
		if b[0] == '#' {
			// comment line - ignore
			continue
		}

		name, args := b, ""

		if idx := bytes.IndexByte(b, ' '); idx != -1 {
			name, args = b[:idx], string(b[idx+1:])
		}

		var err error

		if handler, ok := commands[string(name)]; ok {
			err = handler(args, stdout)
		} else {
			_, err = io.WriteString(stdout, "ERR Unknown command\n")
		}

		if err != nil {
			panic(err)
		}
	}

	if err := stdin.Err(); err != nil {
		panic(err)
	}
}
