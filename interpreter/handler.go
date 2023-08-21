package interpreter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

// Implements http.Handler
func (i *Interpreter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := context.New(i.options...)

	main, err := ctx.Resolver.MainVCL()
	if err != nil {
		i.Debugger.Message(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := checkFastlyVCLLimitation(main.Data); err != nil {
		i.Debugger.Message(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vcl, err := parser.New(
		lexer.NewFromString(main.Data, lexer.WithFile(main.Name)),
	).ParseVCL()
	if err != nil {
		// parse error
		i.Debugger.Message(err.Error())
		http.Error(w, fmt.Sprintf("%+v", err), http.StatusInternalServerError)
		return
	}

	// If remote snippets exists, prepare parse and prepend to main VCL
	if ctx.FastlySnippets != nil {
		for _, snip := range ctx.FastlySnippets.EmbedSnippets() {
			s, err := parser.New(
				lexer.NewFromString(snip.Data, lexer.WithFile(snip.Name)),
			).ParseVCL()
			if err != nil {
				// parse error
				i.Debugger.Message(err.Error())
				http.Error(w, fmt.Sprintf("%+v", err), http.StatusInternalServerError)
				return
			}
			vcl.Statements = append(s.Statements, vcl.Statements...)
		}
	}

	ctx.RequestStartTime = time.Now()
	i.ctx = ctx
	i.ctx.Request = r
	i.process = process.New()

	if err := i.ProcessInit(vcl.Statements); err != nil {
		// If debug is true, print with stacktrace
		i.process.Error = err
		if i.ctx.Debug {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		}
		if re, ok := errors.Cause(err).(*exception.Exception); ok {
			i.Debugger.Message(re.Error())
		} else {
			i.Debugger.Message(err.Error())
		}
	}

	i.process.Restarts = i.ctx.Restarts
	i.process.Backend = i.ctx.Backend
	if i.process.Error != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(i.process) // nolint: errcheck

	i.Debugger.Message("Reuqest finished.")
}
